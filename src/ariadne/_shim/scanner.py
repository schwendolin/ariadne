"""Ausgabe-Scanner des Shims (Architektur 3.3, 3.8). Nur Standardbibliothek.

Trennt den Output des Kindes in Anzeige und Aufnahme:

* ``OSC 7701`` (Ariadne-Marker) verschwindet aus beiden und wird gemeldet.
* ``OSC 0/2`` (Titel) fehlt in der Anzeige, bleibt aber in der Aufnahme.
* ``OSC 52`` und reflektierende Anfragen (``CSI 20 t``, ``CSI 21 t``,
  ``CSI 8;..;.. t``, ``DECRQSS``) verschwinden aus beiden.
* ``CSI 22/23 t`` (Titel-Stapel) fehlt nur in der Anzeige, sonst könnte ein
  Ziel einen alten REC-Titel zurückholen.
* Alles andere läuft unverändert durch, auch fremde ``OSC 133``.

Der Parser folgt dem VT500-Zustandsautomaten: C0-Zeichen innerhalb von ESC
und CSI werden übersprungen (Terminals führen sie aus und setzen die Sequenz
fort), CAN und SUB brechen ab, ESC beginnt eine neue Sequenz. Unvollständige
Sequenzen werden über Chunk-Grenzen gehalten, höchstens 8 KiB bzw. 100 ms,
danach gehen sie als normale Bytes weiter. Das Ergebnis hängt (bis auf diese
Zeitgrenze) nicht davon ab, wie der Strom in Chunks zerfällt.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "MAX_STRING",
    "MAX_HOLD_S",
    "Marker",
    "Forged",
    "Title",
    "Osc52",
    "AltScreen",
    "Dropped",
    "ScanResult",
    "OutputScanner",
]

MAX_STRING = 8 * 1024  # OSC, DCS, APC, PM, SOS
MAX_CSI = 512
MAX_ESC = 32
MAX_HOLD_S = 0.1

ESC = 0x1B
BEL = 0x07
CAN = 0x18
SUB = 0x1A

_CSI_FAST = re.compile(rb"\x1b\[([0-?]*)([ -/]*)([@-~])")
# Läufe aus normalem Text und Sequenzen, die der Scanner nie verändert: CSI ohne
# Präfix und ohne Endbyte t, CSI ? ohne h/l oder ohne Alternate-Screen-Modus,
# CSI mit < = > oder Zwischenzeichen, einfache ESC-Sequenzen. Alles andere geht
# über den langsamen Pfad.
_RUN = re.compile(
    rb"(?:[^\x1b]+"
    rb"|\x1b\[[0-9;:]*[@-su-~]"
    rb"|\x1b\[\?[0-9;:]*[@-gi-km-~]"
    rb"|\x1b\[\?(?!0*(?:47|1047|1049)(?![0-9]))[0-9]*"
    rb"(?:[;:](?!0*(?:47|1047|1049)(?![0-9]))[0-9]*)*[hl]"
    rb"|\x1b\[[<=>][0-?]*[ -/]*[@-~]"
    rb"|\x1b\[[0-?]*[ -/]+[@-~]"
    rb"|\x1b[ -/]+[0-~]"
    rb"|\x1b[0-9:;<=>?@A-OQ-WYZ\\`a-~]"
    rb")+"
)
_STR_STOP = re.compile(rb"[\x07\x1b\x18\x1a]")
_DECRQSS = re.compile(rb"[\x00-\x17\x19\x1c-\x1f0-?]*\$q")
_PEND_MARKER = re.compile(rb"\x1b[\x00-\x17\x19\x1c-\x1f]*\]0*7701;")
_ALT_MODES = {1049, 1047, 47}
_T_REFLECT = {8, 20, 21}  # Fenstergrösse setzen, Icon- und Titel-Report
_T_STACK = {22, 23}  # Titel-Stapel


def _num(b: bytes) -> int | None:
    """Numerischer Parameter wie im Terminal (führende Nullen erlaubt)."""
    if not b or len(b) > 9 or not b.isdigit():
        return None
    return int(b)


@dataclass(frozen=True)
class Marker:
    """Vollständiger ``OSC 7701``-Marker; ``payload`` beginnt mit ``7701;``."""

    payload: bytes
    stream_off: int


@dataclass(frozen=True)
class Forged:
    """Marker-Rest, der nie gültig werden kann (Übergrösse, Abbruch, Zeitlimit)."""

    reason: str  # oversize | malformed
    stream_off: int


@dataclass(frozen=True)
class Title:
    text: bytes
    stream_off: int


@dataclass(frozen=True)
class Osc52:
    length: int
    stream_off: int
    query: bool


@dataclass(frozen=True)
class AltScreen:
    on: bool
    stream_off: int


@dataclass(frozen=True)
class Dropped:
    """Entfernte reflektierende Anfrage (nur für Diagnose und Tests)."""

    what: str
    stream_off: int


ScanItem = Marker | Forged | Title | Osc52 | AltScreen | Dropped


@dataclass
class ScanResult:
    display: bytes = b""
    record: bytes = b""
    items: list[ScanItem] = field(default_factory=list)


class _Out:
    __slots__ = ("disp", "rec", "items", "offset")

    def __init__(self, offset: int) -> None:
        self.disp: list[bytes] = []
        self.rec: list[bytes] = []
        self.items: list[ScanItem] = []
        self.offset = offset

    def plain(self, b: bytes) -> None:
        if b:
            self.disp.append(b)
            self.rec.append(b)
            self.offset += len(b)

    def record_only(self, b: bytes) -> None:
        if b:
            self.rec.append(b)
            self.offset += len(b)

    def result(self) -> ScanResult:
        return ScanResult(b"".join(self.disp), b"".join(self.rec), self.items)


def _is_c0_exec(b: int) -> bool:
    """C0-Zeichen, die ein VT500-Parser mitten in einer Sequenz ausführt."""
    return b < 0x20 and b not in (ESC, CAN, SUB)


class OutputScanner:
    """Zustandsbehafteter Scanner für den Output-Strom eines Terminals."""

    def __init__(self, *, fast: bool = True) -> None:
        self._fast = fast
        self.offset = 0  # aufgezeichnete Bytes seit Start
        self.alt_screen = False
        self._pend = b""
        self._pend_since = 0.0

    # ------------------------------------------------------------------ API

    def feed(self, data: bytes, now: float) -> ScanResult:
        out = _Out(self.offset)
        since = self._pend_since if self._pend else now
        if self._pend:
            data = self._pend + data
            self._pend = b""
        elif ESC not in data:
            out.plain(data)
            self.offset = out.offset
            return out.result()
        self._scan(data, out, since, now)
        self.offset = out.offset
        return out.result()

    def deadline(self) -> float | None:
        return self._pend_since + MAX_HOLD_S if self._pend else None

    def pending(self) -> int:
        return len(self._pend)

    def expire(self, now: float) -> ScanResult:
        """Gibt eine zu lange gehaltene Sequenz als normale Bytes weiter."""
        out = _Out(self.offset)
        if self._pend and now >= self._pend_since + MAX_HOLD_S:
            pend, self._pend = self._pend, b""
            if _PEND_MARKER.match(pend):
                out.items.append(Forged("malformed", out.offset))
            out.plain(pend)
        self.offset = out.offset
        return out.result()

    # ------------------------------------------------------------- Parsing

    def _scan(self, data: bytes, out: _Out, since: float, now: float) -> None:
        n = len(data)
        i = 0
        run = _RUN.match if self._fast else None
        while i < n:
            if run is not None:
                m = run(data, i)
                if m is not None:
                    out.plain(data[i : m.end()])
                    i = m.end()
                    if i >= n:
                        return
            j = data.find(b"\x1b", i)
            if j < 0:
                out.plain(data[i:])
                return
            if j > i:
                out.plain(data[i:j])
            nxt = self._escape(data, j, out)
            if nxt < 0:
                self._pend = data[j:]
                self._pend_since = since if j == 0 else now
                return
            i = nxt

    def _escape(self, data: bytes, j: int, out: _Out) -> int:
        """Verarbeitet die Sequenz ab ``data[j] == ESC``.

        Gibt den Index nach der Sequenz zurück oder -1, wenn Daten fehlen.
        """
        n = len(data)
        k = j + 1
        while k < n and _is_c0_exec(data[k]):
            k += 1
            if k - j > MAX_ESC:
                out.plain(data[j:k])
                return k
        if k >= n:
            return -1
        c = data[k]
        if c == 0x5B:  # [
            return self._csi(data, j, k, out)
        if c == 0x5D:  # ]
            return self._string(data, j, k, out, "osc")
        if c == 0x50:  # P
            return self._string(data, j, k, out, "dcs")
        if c in (0x5F, 0x5E, 0x58):  # _ ^ X
            return self._string(data, j, k, out, "apc")
        if c in (CAN, SUB):
            out.plain(data[j : k + 1])
            return k + 1
        if c == ESC:
            out.plain(data[j:k])
            return k
        if 0x20 <= c <= 0x2F:  # Zwischenzeichen, z. B. ESC ( B
            p = k
            while p < n and (0x20 <= data[p] <= 0x2F or _is_c0_exec(data[p])):
                p += 1
                if p - j > MAX_ESC:
                    out.plain(data[j:p])
                    return p
            if p >= n:
                return -1
            if 0x30 <= data[p] <= 0x7E:
                out.plain(data[j : p + 1])
                return p + 1
            out.plain(data[j:p])
            return p
        # Zweibyte-Sequenz (ESC 7, ESC c ...) oder ESC vor einem Nicht-ASCII-Byte
        if c >= 0x80:
            out.plain(data[j:k])
            return k
        out.plain(data[j : k + 1])
        return k + 1

    # ---------------------------------------------------------------- CSI

    def _csi(self, data: bytes, j: int, k: int, out: _Out) -> int:
        if k == j + 1:
            m = _CSI_FAST.match(data, j)
            if m is not None:
                self._csi_done(data[j : m.end()], m.group(1), m.group(2), m.group(3), out)
                return m.end()
        n = len(data)
        p = k + 1
        params = bytearray()
        inter = bytearray()
        while p < n:
            b = data[p]
            if 0x40 <= b <= 0x7E:
                self._csi_done(data[j : p + 1], bytes(params), bytes(inter), bytes((b,)), out)
                return p + 1
            if 0x30 <= b <= 0x3F:
                params.append(b)
            elif 0x20 <= b <= 0x2F:
                inter.append(b)
            elif b in (CAN, SUB):
                out.plain(data[j : p + 1])
                return p + 1
            elif b == ESC or b >= 0x80:
                out.plain(data[j:p])
                return p
            # C0 und DEL: ausgeführt bzw. ignoriert, die Sequenz läuft weiter
            p += 1
            if p - j > MAX_CSI:
                out.plain(data[j:p])
                return p
        return -1

    def _csi_done(self, seq: bytes, params: bytes, inter: bytes, final: bytes, out: _Out) -> None:
        if final == b"t" and not inter and params[:1] not in (b"<", b"=", b">", b"?"):
            first = _num(params.split(b";", 1)[0].split(b":", 1)[0])
            if first in _T_REFLECT:
                out.items.append(Dropped("csi_t", out.offset))
                return
            if first in _T_STACK:
                out.record_only(seq)
                return
        elif final in (b"h", b"l") and params.startswith(b"?") and not inter:
            modes = {_num(x) for x in params[1:].split(b";")}
            if modes & _ALT_MODES:
                on = final == b"h"
                if on != self.alt_screen:
                    self.alt_screen = on
                    out.items.append(AltScreen(on, out.offset))
        out.plain(seq)

    # ------------------------------------------------ OSC, DCS, APC, PM, SOS

    def _string(self, data: bytes, j: int, k: int, out: _Out, kind: str) -> int:
        n = len(data)
        limit = j + MAX_STRING
        p = k + 1
        m = _STR_STOP.search(data, p, min(n, limit))
        if m is None:
            if n >= limit:
                return self._oversize(data, j, k, out, kind)
            return -1
        t = m.start()
        b = data[t]
        if b == BEL:
            self._string_done(data, j, k, t, t + 1, out, kind)
            return t + 1
        if b == ESC:
            if t + 1 >= n:
                return -1
            if data[t + 1] == 0x5C:  # ST
                self._string_done(data, j, k, t, t + 2, out, kind)
                return t + 2
            self._string_abort(data, j, k, t, out, kind)
            return t
        # CAN oder SUB: Abbruch, das Zeichen selbst geht mit durch
        self._string_abort(data, j, k, t + 1, out, kind)
        return t + 1

    def _is_marker(self, data: bytes, k: int, kind: str) -> bool:
        if kind != "osc":
            return False
        code = data[k + 1 : k + 12].partition(b";")[0]
        return _num(code) == 7701

    def _oversize(self, data: bytes, j: int, k: int, out: _Out, kind: str) -> int:
        end = j + MAX_STRING
        if self._is_marker(data, k, kind):
            out.items.append(Forged("oversize", out.offset))
        out.plain(data[j:end])
        return end

    def _string_abort(self, data: bytes, j: int, k: int, end: int, out: _Out, kind: str) -> None:
        if self._is_marker(data, k, kind):
            out.items.append(Forged("malformed", out.offset))
            return
        out.plain(data[j:end])

    def _string_done(self, data: bytes, j: int, k: int, t: int, end: int, out: _Out, kind: str) -> None:
        body = data[k + 1 : t]
        seq = data[j:end]
        if kind == "osc":
            raw_code, _, rest = body.partition(b";")
            code = _num(raw_code)
            if code == 7701:
                out.items.append(Marker(body, out.offset))
                return
            if code in (0, 2):
                out.items.append(Title(rest, out.offset))
                out.record_only(seq)
                return
            if code == 52:
                _sel, _, payload = rest.partition(b";")
                out.items.append(Osc52(len(seq), out.offset, payload == b"?"))
                return
        elif kind == "dcs" and _DECRQSS.match(body):
            out.items.append(Dropped("decrqss", out.offset))
            return
        out.plain(seq)
