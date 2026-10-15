"""Redaktor für eigene Secrets (Architektur 8.5). Es gibt genau diesen einen.

Läuft im Writer des Daemons, vor Hash und Persistenz. Der Shim bekommt keine
Secret-Liste.

* Gesucht wird nach jedem eigenen Secret wörtlich, URL-kodiert und
  JSON-escaped, und zwar auf einer Sicht ohne ANSI-Sequenzen (CSI, OSC, DCS
  und andere ESC-Folgen). So fällt auch ein Echo auf, das
  ``zsh-syntax-highlighting`` mit Farbsequenzen zerstückelt hat.
* Ein Treffer ersetzt den ganzen zugehörigen Rohbereich (inklusive der
  eingestreuten Sequenzen) durch ``*`` gleicher Länge. Offsets bleiben stabil.
* Inhalte von OSC- und DCS-Strings (Fenstertitel mit der Befehlszeile, OSC 8
  mit Token in der URL) werden zusätzlich je für sich durchsucht.
* Pro Terminal bleiben die letzten ``max_len - 1`` Zeichen der Sicht (plus eine
  unvollständige Sequenz am Ende) zurück, damit Treffer über Chunk-Grenzen
  erkannt werden, auch nach einer Korrektur mit Backspace (die Sicht wendet
  Backspace an). :meth:`Redactor.flush` gibt den Rückhalt frei;
  ``keep_prefix=True`` (Stille) behält nur ein Ende, das ein Secret beginnen
  könnte, damit eine Pause beim Tippen nichts verrät.

Generische Muster (Private Keys, ``sk-ant-``, ``AKIA``) schwärzt der Redaktor
nie, denn Secrets vom Ziel sind Funde. :func:`scan_outgoing` meldet sie nur als
Warnung vor Exporten und KI-Aufrufen.
"""

from __future__ import annotations

import bisect
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import quote, quote_plus

from ariadne.events import Redaction

__all__ = [
    "Redactor",
    "Chunk",
    "Hit",
    "OutgoingWarning",
    "scan_outgoing",
    "variants",
    "FILL",
]

FILL = 0x2A  # '*'
MAX_ESC = 8192  # längere Sequenzen gelten als Text (wie im Shim, Architektur 3.8)

# Vollständige Sequenzen: CSI, OSC (BEL oder ST), DCS/SOS/PM/APC (ST), sonstige ESC-Folgen.
_ESC_RE = re.compile(
    rb"\x1b\[[\x30-\x3f]*[\x20-\x2f]*[\x40-\x7e]"
    rb"|\x1b\][^\x07\x1b]{0,8192}(?:\x07|\x1b\\)"
    rb"|\x1b[PX^_][^\x1b]{0,8192}\x1b\\"
    rb"|\x1b[\x20-\x2f]*[\x30-\x7e]"
)
# Unvollständige Sequenz am Pufferende (kann mit dem nächsten Chunk vollständig werden).
_ESC_TAIL_RE = re.compile(
    rb"\x1b(?:\[[\x30-\x3f]*[\x20-\x2f]*|\][^\x07\x1b]*\x1b?|[PX^_][^\x1b]*\x1b?|[\x20-\x2f]*)\Z"
)

Chunk = tuple[int, bytes, list[Redaction]]


@dataclass(frozen=True)
class Hit:
    label: str
    start: int
    end: int


@dataclass(frozen=True)
class OutgoingWarning:
    kind: str
    start: int
    end: int


def variants(value: str) -> set[bytes]:
    """Alle gesuchten Kodierungen eines Secrets."""
    out = {value.encode()}
    out.add(quote(value, safe="").encode())
    out.add(quote_plus(value, safe="").encode())
    out.add(json.dumps(value, ensure_ascii=False)[1:-1].encode())
    out.add(json.dumps(value, ensure_ascii=True)[1:-1].encode())
    return out


class _View:
    """Sicht ohne Escape-Sequenzen mit Rückabbildung auf Roh-Offsets.

    ``strings`` sind die Rohbereiche der Inhalte von OSC- und DCS-Strings; sie
    gehören nicht zur Sicht, werden aber einzeln durchsucht.
    """

    __slots__ = ("text", "_vstarts", "_rstarts", "limit", "strings", "etext", "_eraw")

    def __init__(self, buf: bytes, limit: int) -> None:
        self.limit = limit  # Rohbytes ab hier gehören nicht zur Sicht
        parts: list[bytes] = []
        vstarts: list[int] = []
        rstarts: list[int] = []
        self.strings: list[tuple[int, int]] = []
        pos = 0
        vlen = 0
        if b"\x1b" in buf[:limit]:
            for m in _ESC_RE.finditer(buf, 0, limit):
                if m.start() > pos:
                    vstarts.append(vlen)
                    rstarts.append(pos)
                    parts.append(buf[pos:m.start()])
                    vlen += m.start() - pos
                if buf[m.start() + 1] in (0x5D, 0x50):  # OSC, DCS: Inhalt ohne Einleitung/Terminator
                    end = m.end() - (1 if buf[m.end() - 1] == 0x07 else 2)
                    if end > m.start() + 2:
                        self.strings.append((m.start() + 2, end))
                pos = m.end()
        if limit > pos:
            vstarts.append(vlen)
            rstarts.append(pos)
            parts.append(buf[pos:limit])
        self.text = b"".join(parts)
        self._vstarts = vstarts
        self._rstarts = rstarts
        # Zeilenbearbeitung beim Tippen: Backspace löscht das Zeichen davor ("hunx" BS
        # ESC[K "ter2"). Zusätzlich zur Sicht wird der bearbeitete Text durchsucht; ein
        # Treffer dort schwärzt den ganzen Rohbereich samt gelöschter Zeichen.
        self.etext: bytes | None = None
        self._eraw: list[int] = []
        if b"\x08" in self.text:
            vb = bytearray()
            for part, rstart in zip(parts, rstarts, strict=True):
                for k, ch in enumerate(part):
                    if ch == 0x08:
                        if vb:
                            vb.pop()
                            self._eraw.pop()
                    else:
                        vb.append(ch)
                        self._eraw.append(rstart + k)
            self.etext = bytes(vb)

    def raw(self, vi: int) -> int:
        """Roh-Offset des Sichtzeichens ``vi`` (0 <= vi < len(text))."""
        k = bisect.bisect_right(self._vstarts, vi) - 1
        return self._rstarts[k] + (vi - self._vstarts[k])


class _State:
    __slots__ = ("base", "buf")

    def __init__(self, base: int) -> None:
        self.base = base
        self.buf = b""

    @property
    def end(self) -> int:
        return self.base + len(self.buf)


class Redactor:
    """Längenerhaltende Schwärzung eigener Secrets in Output-Strömen.

    ``feed`` liefert ``(stream_off, bytes, [Redaction])``-Stücke in Strom-Reihenfolge.
    Die Summe aller gelieferten Stücke ergibt exakt den eingegebenen Strom,
    nur mit ``*`` an Stelle der Treffer.
    """

    def __init__(self, secrets: Iterable[tuple[str, str]] = (), min_len: int = 4,
                 max_hold_raw: int = 64 * 1024) -> None:
        self.min_len = min_len
        self.max_hold_raw = max_hold_raw
        self._states: dict[str, _State] = {}
        self._patterns: list[tuple[bytes, str]] = []
        self.max_len = 0
        self.update_secrets(secrets)

    # ------------------------------------------------------------------ #
    def update_secrets(self, secrets: Iterable[tuple[str, str]]) -> None:
        pats: dict[bytes, str] = {}
        for label, value in secrets:
            if not value or len(value) < self.min_len:
                continue
            for v in variants(value):
                if len(v) >= self.min_len:
                    pats.setdefault(v, label)
        # Längere Muster zuerst, damit sie bei Überlappung das Label bestimmen.
        self._patterns = sorted(pats.items(), key=lambda p: -len(p[0]))
        self.max_len = max((len(p) for p in pats), default=0)

    @property
    def active(self) -> bool:
        return bool(self._patterns)

    def pending(self, terminal_id: str) -> tuple[int, int] | None:
        st = self._states.get(terminal_id)
        if st is None or not st.buf:
            return None
        return st.base, len(st.buf)

    def terminals_with_pending(self) -> list[str]:
        return [t for t, st in self._states.items() if st.buf]

    # ------------------------------------------------------------------ #
    def _find(self, view: _View, buf: bytes = b"") -> list[Hit]:
        """Treffer in der Sicht, abgebildet auf Roh-Bereiche, überlappende zusammengeführt."""
        text = view.text
        raw_hits: list[Hit] = []
        for pat, label in self._patterns:
            i = text.find(pat)
            while i >= 0:
                raw_hits.append(Hit(label, view.raw(i), view.raw(i + len(pat) - 1) + 1))
                i = text.find(pat, i + 1)
            for a, b in view.strings:
                i = buf.find(pat, a, b)
                while i >= 0:
                    raw_hits.append(Hit(label, i, i + len(pat)))
                    i = buf.find(pat, i + 1, b)
            if view.etext is not None:
                er = view._eraw
                i = view.etext.find(pat)
                while i >= 0:
                    raw_hits.append(Hit(label, er[i], er[i + len(pat) - 1] + 1))
                    i = view.etext.find(pat, i + 1)
        if not raw_hits:
            return []
        raw_hits.sort(key=lambda h: (h.start, -(h.end - h.start)))
        merged: list[Hit] = [raw_hits[0]]
        for h in raw_hits[1:]:
            last = merged[-1]
            if h.start < last.end:
                if h.end > last.end:
                    merged[-1] = Hit(last.label, last.start, h.end)
            else:
                merged.append(h)
        return merged

    def scan(self, data: bytes) -> list[Hit]:
        """Alle Treffer in einem vollständigen Puffer (Roh-Offsets relativ zu ``data``)."""
        if not self._patterns:
            return []
        return self._find(_View(data, len(data)), data)

    def _prefix_hold(self, text: bytes) -> int:
        """Länge des längsten Endes von ``text``, mit dem ein gesuchtes Muster beginnt."""
        best = 0
        tail = text[-(self.max_len - 1):] if self.max_len > 1 else b""
        for pat, _label in self._patterns:
            start = max(0, len(tail) - (len(pat) - 1))
            i = tail.find(pat[:1], start)
            while i >= 0:
                k = len(tail) - i
                if k <= best:
                    break
                if pat.startswith(tail[i:]):
                    best = k
                    break
                i = tail.find(pat[:1], i + 1)
        return best

    def _process(self, st: _State, final: bool, keep_prefix: bool = False) -> Chunk | None:
        buf = st.buf
        if not buf:
            return None
        if not self._patterns:
            emit = len(buf)
            hits: list[Hit] = []
        else:
            limit = len(buf)
            if not final and not keep_prefix:
                tail = _ESC_TAIL_RE.search(buf, max(0, len(buf) - MAX_ESC))
                if tail is not None:
                    limit = tail.start()
            view = _View(buf, limit)
            hits = self._find(view, buf)
            if final:
                emit = len(buf)
            else:
                # Normal: die letzten max_len - 1 Zeichen warten (ein Secret kann noch
                # kommen, auch nach einer Korrektur mit Backspace). Im Leerlauf nur ein
                # echter Secret-Anfang, sonst stünde das Stromende ewig zurück.
                hold = self._prefix_hold(view.text) if keep_prefix else self.max_len - 1
                n = len(view.text)
                emit = limit if not n or not hold else view.raw(max(0, n - hold))
                if view.etext is not None:  # bearbeiteter Text: gleich viele Zeichen zurückhalten
                    ehold = self._prefix_hold(view.etext) if keep_prefix else self.max_len - 1
                    en = len(view.etext)
                    if en and ehold:
                        emit = min(emit, view._eraw[max(0, en - ehold)])
                emit = min(emit, limit)
                if len(buf) - emit > self.max_hold_raw:
                    emit = len(buf) - self.max_hold_raw
            applied: list[Hit] = []
            for h in hits:
                if h.start < emit:
                    emit = max(emit, h.end)
                    applied.append(h)
            hits = applied
        if emit <= 0:
            return None
        out = bytearray(buf[:emit])
        reds: list[Redaction] = []
        for h in hits:
            out[h.start:h.end] = bytes([FILL]) * (h.end - h.start)
            reds.append(Redaction(label=h.label, start=st.base + h.start, end=st.base + h.end))
        chunk = (st.base, bytes(out), reds)
        st.base += emit
        st.buf = buf[emit:]
        return chunk

    # ------------------------------------------------------------------ #
    def feed(self, terminal_id: str, stream_off: int, data: bytes) -> list[Chunk]:
        """Nimmt ein Stück des Stroms an und liefert alles, was sicher ausgegeben werden kann."""
        out: list[Chunk] = []
        st = self._states.get(terminal_id)
        if st is not None and st.buf and stream_off != st.end:
            # Lücke oder Überlappung: Rückhalt vollständig ausgeben, neu beginnen.
            done = self._process(st, final=True)
            if done:
                out.append(done)
            st = None
        if st is None or not st.buf:
            st = _State(stream_off)
            self._states[terminal_id] = st
        st.buf += bytes(data)
        done = self._process(st, final=False)
        if done:
            out.append(done)
        return out

    def flush(self, terminal_id: str, *, keep_prefix: bool = False) -> list[Chunk]:
        """Gibt den Rückhalt eines Terminals frei (REC aus, Projektwechsel, Ende).

        ``keep_prefix=True`` (Leerlauf): Ein Ende, das ein Secret beginnen könnte,
        bleibt zurück. Sonst gäbe eine Pause beim Tippen den Anfang frei, und der
        Rest würde nicht mehr erkannt.
        """
        if keep_prefix:
            st = self._states.get(terminal_id)
            if st is None:
                return []
            done = self._process(st, final=False, keep_prefix=True)
            if not st.buf:
                self._states.pop(terminal_id, None)
            return [done] if done else []
        st = self._states.pop(terminal_id, None)
        if st is None:
            return []
        done = self._process(st, final=True)
        return [done] if done else []

    def drop(self, terminal_id: str) -> None:
        """Verwirft den Rückhalt ohne Ausgabe (nur für Abbruch)."""
        self._states.pop(terminal_id, None)

    def scan_outgoing(self, text: str) -> tuple[list[Hit], list[OutgoingWarning]]:
        """Eigene Treffer und generische Warnungen vor Export oder KI-Aufruf (siehe :func:`scan_outgoing`)."""
        return scan_outgoing(text, self)

    # ------------------------------------------------------------------ #
    def redact_text(self, text: str, *, truncated: bool = False) -> tuple[str, list[str]]:
        """Schwärzt eigene Secrets in einem Text (z. B. Befehlszeile im Marker).

        ``truncated``: Der Text wurde an einer Längengrenze abgeschnitten. Endet er
        mit dem Anfang eines eigenen Secrets (mindestens ``min_len`` Zeichen), wird
        auch dieser Anfang geschwärzt; sonst stünde er im Klartext im Journal.
        """
        if not self._patterns or not text:
            return text, []
        data = text.encode("utf-8", "surrogateescape")
        hits = self.scan(data)
        labels = {h.label for h in hits}
        out = bytearray(data)
        for h in hits:
            out[h.start:h.end] = bytes([FILL]) * (h.end - h.start)
        if truncated:
            k = self._prefix_hold(bytes(out))
            if k >= self.min_len:
                out[len(out) - k:] = bytes([FILL]) * k
                labels.add("truncated")
        if not labels:
            return text, []
        return out.decode("utf-8", "replace"), sorted(labels)


# --------------------------------------------------------------------------- #
# Prüfung ausgehender Daten (Export, KI)
# --------------------------------------------------------------------------- #

_GENERIC = [
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")),
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
]


def scan_outgoing(text: str, redactor: Redactor | None = None) -> tuple[list[Hit], list[OutgoingWarning]]:
    """Prüft Text vor Export oder KI-Aufruf.

    Liefert eigene Treffer (Offsets in UTF-8-Bytes) und generische Warnungen
    (Offsets in Zeichen). Geschwärzt wird hier nichts.
    """
    own = redactor.scan(text.encode("utf-8", "surrogateescape")) if redactor is not None else []
    warnings = [OutgoingWarning(kind, m.start(), m.end())
                for kind, rx in _GENERIC for m in rx.finditer(text)]
    warnings.sort(key=lambda w: w.start)
    return own, warnings
