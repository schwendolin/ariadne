"""Terminal-Normalizer mit Offset-Karte (Architektur 5.5).

Genau ein Normalizer, zeilenbasiert. Eingabe sind Rohbytes eines
Stream-Bereichs mit absolutem Start-Offset, Ausgabe :class:`NormLine` mit
Spalten-zu-Roh-Offset-Karte (``to_line()`` liefert ``ariadne.parsers.api.Line``).

* UTF-8 inkrementell; kaputte Bytes werden U+FFFD (je maximalem Teilstück)
  mit dem Offset ihres ersten Bytes. Spalten zählen Codepoints, nicht Zellen.
* Escape-Sequenzen nach dem VT500-Automaten: CSI, OSC (BEL/ST), DCS, SOS, PM,
  APC (ST), einfache ESC-Folgen. C0 in Sequenzen wird ausgeführt, CAN/SUB
  bricht ab. OSC und Co. höchstens 8 KiB, CSI höchstens 512 Byte, danach
  normaler Text (wie im Shim).
* SGR wird als Spannen pro Zeile ausgewertet (Farben 8/16/256/RGB, fett,
  verdeckt) und dann entfernt. Verdeckt heisst SGR 8 oder gleiche Vorder- und
  Hintergrundfarbe.
* Eine Zeile ist eine logische Zeile (bis LF). Ist die Terminalbreite bekannt,
  wird der automatische Umbruch nachgebildet: ``\\r``, ``\\b``, ``ESC[K`` und
  Cursorbewegungen wirken auf die physische Zeile, umbrochener Text bleibt eine
  logische Zeile. ``\\r\\n`` ist ein Zeilenende. Cursor hoch (A, F, ESC M)
  reicht bis zu 50 vorige Zeilen zurück. Überschriebener oder gelöschter Text
  setzt ``overwritten``.
* Alternate Screen (``?1049``, ``?1047``, ``?47``): Inhalt geht an ``pyte`` und
  ergibt nur ein Schlussbild als Zeilen mit Flag ``altscreen`` (nicht parsen).
* :meth:`Normalizer.boundary` (Marker, Lücken) beendet die laufende Zeile,
  schliesst den Alternate Screen und setzt den Terminalzustand zurück. Danach
  hängt das Ergebnis nur noch von den folgenden Bytes ab, so lässt sich an jeder
  Grenze neu aufsetzen. ``prompt=True`` markiert die folgenden Zeilen als
  ``prompt_echo`` (Bereich A..C).

Das Ergebnis hängt nicht davon ab, wie der Strom in Chunks zerfällt.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from ariadne.parsers.api import Line, SgrSpan

__all__ = [
    "NORMALIZER_VERSION",
    "FLAG_PROMPT",
    "FLAG_CONCEALED",
    "FLAG_OVERWRITTEN",
    "FLAG_ALTSCREEN",
    "FLAG_WRAPPED",
    "NormLine",
    "Normalizer",
    "normalize",
    "colmap_lookup",
    "colmap_to_json",
    "colmap_from_json",
    "sgr_to_json",
    "sgr_from_json",
]

NORMALIZER_VERSION = 1

FLAG_PROMPT = 1
FLAG_CONCEALED = 2
FLAG_OVERWRITTEN = 4
FLAG_ALTSCREEN = 8
FLAG_WRAPPED = 16  # Zeile wurde bei MAX_COLS hart umbrochen

MAX_COLS = 16384
MAX_UP = 50
MAX_STRING = 8192
MAX_CSI = 512
MAX_ALT_BYTES = 1 << 20
MAX_PARAM = 65535

_GROUND, _ESC, _ESC_INT, _CSI, _STR, _STR_ESC = range(6)
_TEXT = re.compile(
    rb"(?:[\x20-\x7e]+|(?:[\xc2-\xdf][\x80-\xbf]|\xe0[\xa0-\xbf][\x80-\xbf]"
    rb"|[\xe1-\xec\xee\xef][\x80-\xbf]{2}|\xed[\x80-\x9f][\x80-\xbf]"
    rb"|\xf0[\x90-\xbf][\x80-\xbf]{2}|[\xf1-\xf3][\x80-\xbf]{3}|\xf4[\x80-\x8f][\x80-\xbf]{2})+)+"
)
_CSI_FAST = re.compile(rb"\x1b\[([0-?]*)([ -/]*)([@-~])")
_STR_STOP_OSC = re.compile(rb"[\x07\x1b\x18\x1a]")
_STR_STOP_ST = re.compile(rb"[\x1b\x18\x1a]")
_UTF8_RANGES: dict[int, tuple[tuple[int, int], ...]] = {}
for _b in range(0xC2, 0xE0):
    _UTF8_RANGES[_b] = ((0x80, 0xBF),)
_UTF8_RANGES[0xE0] = ((0xA0, 0xBF), (0x80, 0xBF))
for _b in [*range(0xE1, 0xED), 0xEE, 0xEF]:
    _UTF8_RANGES[_b] = ((0x80, 0xBF), (0x80, 0xBF))
_UTF8_RANGES[0xED] = ((0x80, 0x9F), (0x80, 0xBF))
_UTF8_RANGES[0xF0] = ((0x90, 0xBF), (0x80, 0xBF), (0x80, 0xBF))
for _b in range(0xF1, 0xF4):
    _UTF8_RANGES[_b] = ((0x80, 0xBF), (0x80, 0xBF), (0x80, 0xBF))
_UTF8_RANGES[0xF4] = ((0x80, 0x8F), (0x80, 0xBF), (0x80, 0xBF))

_BASE = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")
_CUBE = (0, 95, 135, 175, 215, 255)


def _palette(n: int) -> str | None:
    if not 0 <= n <= 255:
        return None
    if n < 8:
        return _BASE[n]
    if n < 16:
        return "bright_" + _BASE[n - 8]
    if n < 232:
        n -= 16
        r, g, b = _CUBE[n // 36], _CUBE[(n // 6) % 6], _CUBE[n % 6]
        return f"#{r:02x}{g:02x}{b:02x}"
    v = 8 + 10 * (n - 232)
    return f"#{v:02x}{v:02x}{v:02x}"


@dataclass(frozen=True)
class _Attr:
    fg: str | None = None
    bg: str | None = None
    bold: bool = False
    conceal: bool = False
    inverse: bool = False

    @property
    def concealed(self) -> bool:
        return self.conceal or (self.fg is not None and self.fg == self.bg)

    @property
    def visual(self) -> tuple[str | None, str | None, bool, bool]:
        return (self.fg, self.bg, self.bold, self.concealed)


_DEFAULT = _Attr()
_PLAIN = _DEFAULT.visual


@dataclass(frozen=True)
class NormLine:
    """Normalisierte Zeile mit Flags und Spalten-Karte.

    ``colmap`` ist eine flache Folge von Läufen ``(col, rel, count, step)``:
    Spalte ``col + k`` stammt vom Roh-Offset ``raw_start + rel + k * step``.
    Leer bei Alternate-Screen-Zeilen.
    """

    text: str
    raw_start: int
    raw_end: int
    sgr: tuple[SgrSpan, ...] = ()
    flags: int = 0
    colmap: tuple[int, ...] = ()

    @property
    def prompt_echo(self) -> bool:
        return bool(self.flags & FLAG_PROMPT)

    @property
    def concealed(self) -> bool:
        return bool(self.flags & FLAG_CONCEALED)

    @property
    def overwritten(self) -> bool:
        return bool(self.flags & FLAG_OVERWRITTEN)

    @property
    def altscreen(self) -> bool:
        return bool(self.flags & FLAG_ALTSCREEN)

    def to_line(self) -> Line:
        return Line(self.text, self.raw_start, self.raw_end, self.sgr, self.prompt_echo,
                    self.concealed, self.overwritten)

    def col_to_raw(self, col: int) -> int | None:
        rel = colmap_lookup(self.colmap, col)
        return None if rel is None else self.raw_start + rel


def colmap_lookup(colmap: Sequence[int], col: int) -> int | None:
    """Relativer Roh-Offset der Spalte ``col`` oder ``None``."""
    for i in range(0, len(colmap) - 3, 4):
        c0, rel, count, step = colmap[i], colmap[i + 1], colmap[i + 2], colmap[i + 3]
        if c0 <= col < c0 + count:
            return rel + (col - c0) * step
    return None


def colmap_to_json(colmap: Sequence[int]) -> str | None:
    return json.dumps(list(colmap), separators=(",", ":")) if colmap else None


def colmap_from_json(text: str | None) -> tuple[int, ...]:
    return tuple(int(x) for x in json.loads(text)) if text else ()


def _compress(raws: Sequence[int], base: int) -> tuple[int, ...]:
    out: list[int] = []
    n = len(raws)
    i = 0
    while i < n:
        j = i + 1
        step = raws[j] - raws[i] if j < n else 1
        if step in (1, 2, 3, 4):
            while j < n and raws[j] - raws[j - 1] == step:
                j += 1
        else:
            step = 1
        out += (i, raws[i] - base, j - i, step)
        i = j
    return tuple(out)


def sgr_to_json(spans: Sequence[SgrSpan]) -> str | None:
    if not spans:
        return None
    rows = []
    for s in spans:
        d: dict[str, object] = {"s": s.col_start, "e": s.col_end}
        if s.fg:
            d["fg"] = s.fg
        if s.bg:
            d["bg"] = s.bg
        if s.bold:
            d["b"] = 1
        if s.concealed:
            d["c"] = 1
        rows.append(d)
    return json.dumps(rows, separators=(",", ":"))


def sgr_from_json(text: str | None) -> tuple[SgrSpan, ...]:
    if not text:
        return ()
    return tuple(
        SgrSpan(int(d["s"]), int(d["e"]), d.get("fg"), d.get("bg"), bool(d.get("b")), bool(d.get("c")))
        for d in json.loads(text)
    )


class _Row:
    __slots__ = ("chars", "raws", "attrs", "raw_start", "raw_end", "overwritten", "wrapped", "prompt")

    def __init__(self, raw_start: int, prompt: bool) -> None:
        self.chars: list[str] = []
        self.raws: list[int] = []
        self.attrs: list[_Attr] = []
        self.raw_start = raw_start
        self.raw_end = raw_start
        self.overwritten = False
        self.wrapped = False
        self.prompt = prompt


@dataclass
class _Seq:
    """Zustand einer angefangenen Escape-Sequenz (über Chunk-Grenzen)."""

    start: int = 0  # absoluter Offset des ESC
    params: bytearray = field(default_factory=bytearray)
    inter: bytearray = field(default_factory=bytearray)
    ignore: bool = False
    length: int = 0
    osc: bool = False  # Zeichenkette endet auch mit BEL


class Normalizer:
    """Inkrementeller Normalizer für einen Stream.

    ``feed`` nimmt Bytes (optional mit absolutem Offset; ein Sprung gilt als
    Lücke), ``boundary`` beendet die Zeile an einer Grenze, ``take_final``
    liefert Zeilen, die sich nicht mehr ändern können, ``pending`` die
    vorläufigen, ``finish`` schliesst ab. ``cols`` ist die Terminalbreite
    (0 = unbekannt, dann ohne Umbruch).
    """

    def __init__(self, start: int = 0, *, cols: int = 0, rows: int = 24, prompt: bool = False) -> None:
        self._off = start  # Stream-Offset des nächsten eingehenden Bytes
        self._prompt = prompt
        self._width = 0
        self._height = 24
        self.resize(cols, rows)
        self._done: list[NormLine] = []
        self._rows: list[_Row] = [_Row(start, prompt)]
        self._cur = 0
        self._base_row = 0  # absolute Nummer von self._rows[0]
        self._col = 0  # Index in der logischen Zeile
        self._wrap = False  # Umbruch steht aus (Cursor physisch in der letzten Spalte)
        self._attr = _DEFAULT
        self._saved: tuple[int, int, _Attr] | None = None
        self._last_char: str | None = None
        self._state = _GROUND
        self._seq = _Seq()
        self._pend = b""  # unvollständiges UTF-8 am Ende
        self._pend_off = 0
        self._buf = b""  # aktueller Arbeitspuffer und sein absoluter Start
        self._buf_base = 0
        self._alt_from = 0
        self._alt = False
        self._alt_start = 0
        self._alt_content = 0
        self._alt_buf = bytearray()
        self._alt_dropped = 0
        self._finished = False

    # ------------------------------------------------------------------ API
    @property
    def offset(self) -> int:
        """Offset des nächsten erwarteten Bytes."""
        return self._off

    @property
    def final_off(self) -> int:
        """Alle Zeilen, die vor diesem Offset beginnen, sind endgültig."""
        if self._alt:
            return self._alt_start
        if self._pend:
            return min(self._rows[0].raw_start, self._pend_off)
        return self._rows[0].raw_start

    def resize(self, cols: int, rows: int) -> None:
        self._width = max(0, min(int(cols), 1000))
        self._height = max(1, min(int(rows) or 24, 500))

    def feed(self, data: bytes, offset: int | None = None) -> None:
        if self._finished:
            raise RuntimeError("Normalizer ist abgeschlossen")
        if offset is not None and offset != self._off:
            if offset < self._off:
                raise ValueError("Offsets müssen steigen")
            self._gap(offset)
        if data:
            self._process(bytes(data))

    def boundary(self, off: int | None = None, *, prompt: bool | None = None, eol_mark: bool = False) -> None:
        """Grenze bei ``off`` (Standard: aktueller Offset).

        Beendet die laufende Zeile und setzt den Terminalzustand zurück.
        ``prompt`` setzt den Modus für die folgenden Zeilen. ``eol_mark``
        entfernt die Markierung von zsh ``PROMPT_SP`` (ein invers dargestelltes
        ``%`` oder ``#`` am Ende der letzten Zeile vor einem D-Marker).
        """
        if self._finished:
            raise RuntimeError("Normalizer ist abgeschlossen")
        if off is not None and off != self._off:
            if off < self._off:
                raise ValueError("Grenze liegt vor dem aktuellen Offset")
            self._gap(off)
        self._flush_utf8()
        if self._alt:
            self._alt_close(self._off)
        if eol_mark:
            self._strip_eol_mark()
        if prompt is not None:
            self._prompt = prompt
        self._flush_rows(self._off)
        self._reset_state()

    def take_final(self) -> list[NormLine]:
        out, self._done = self._done, []
        return out

    def pending(self) -> list[NormLine]:
        """Vorläufige Zeilen (können sich noch ändern), ohne leere letzte Zeile."""
        rows = list(self._rows)
        if rows and not "".join(rows[-1].chars).strip():
            rows.pop()
        last = self._rows[-1]
        return [self._line(r, self._off if r is last else r.raw_end) for r in rows]

    def finish(self) -> list[NormLine]:
        if not self._finished:
            self._flush_utf8()
            if self._alt:
                self._alt_close(self._off)
            self._flush_rows(self._off)
            self._finished = True
        return self.take_final()

    # ------------------------------------------------------------- Grenzen
    def _gap(self, new_off: int) -> None:
        self._flush_utf8()
        if self._alt:
            self._alt_close(self._off)
        self._flush_rows(self._off)
        self._reset_state()
        self._off = new_off
        self._reset_window(new_off)

    def _reset_state(self) -> None:
        self._state = _GROUND
        self._seq = _Seq()
        self._attr = _DEFAULT
        self._saved = None
        self._last_char = None

    def _flush_rows(self, off: int) -> None:
        last = self._rows[-1]
        for r in self._rows:
            if r is last:
                if "".join(r.chars).strip():
                    self._done.append(self._line(r, off))
            else:
                self._done.append(self._line(r, r.raw_end))
        self._reset_window(off)

    def _reset_window(self, off: int) -> None:
        self._base_row += len(self._rows)
        self._rows = [_Row(off, self._prompt)]
        self._cur = 0
        self._col = 0
        self._wrap = False

    def _strip_eol_mark(self) -> None:
        row = self._rows[-1]
        n = len(row.chars)
        while n and row.chars[n - 1] == " ":
            n -= 1
        if n and row.chars[n - 1] in "%#" and row.attrs[n - 1].inverse \
                and (n == 1 or not row.attrs[n - 2].inverse):
            del row.chars[n - 1 :], row.raws[n - 1 :], row.attrs[n - 1 :]

    # ---------------------------------------------------------- Hauptschleife
    def _process(self, data: bytes) -> None:
        if self._pend:
            data = self._pend + data
            base = self._pend_off
            self._pend = b""
        else:
            base = self._off
        self._off = base + len(data)
        self._buf, self._buf_base, self._alt_from = data, base, 0
        n = len(data)
        i = 0
        while i < n:
            if self._state != _GROUND:
                i = self._escape_byte(data, i, base)
                continue
            m = _TEXT.match(data, i)
            if m is not None:
                if not self._alt:
                    self._text(m.group(), base + i)
                i = m.end()
                continue
            b = data[i]
            if b == 0x1B:
                fm = _CSI_FAST.match(data, i)
                self._seq = _Seq(start=base + i)
                if fm is not None and fm.end() - i <= MAX_CSI:
                    self._csi(bytes(fm.group(1)), bytes(fm.group(2)), fm.group(3)[0], base + fm.end())
                    i = fm.end()
                else:
                    self._state = _ESC
                    i += 1
                continue
            if b < 0x20 or b == 0x7F:
                if not self._alt:
                    self._control(b, base + i)
                i += 1
                continue
            # ungültiges oder unvollständiges UTF-8
            k, truncated = _utf8_subpart(data, i)
            if truncated:
                self._pend = bytes(data[i:])
                self._pend_off = base + i
                n = i
                break
            if not self._alt:
                self._write("�", (base + i,))
            i += k
        if self._alt:
            self._alt_append(data[self._alt_from : n])
        self._buf = b""

    def _escape_byte(self, data: bytes, i: int, base: int) -> int:
        """Ein Schritt im Escape-Automaten; gibt die neue Position zurück."""
        st = self._state
        seq = self._seq
        b = data[i]
        if st in (_STR, _STR_ESC):
            return self._string(data, i, base)
        if b in (0x18, 0x1A):  # CAN, SUB
            self._state = _GROUND
            return i + 1
        if b == 0x1B:
            self._seq = _Seq(start=base + i)
            self._state = _ESC
            return i + 1
        if b >= 0x80:
            self._state = _GROUND
            return i  # Byte als Text neu verarbeiten
        if b < 0x20:
            if not self._alt:
                self._control(b, base + i)
            return i + 1
        if b == 0x7F:
            return i + 1
        seq.length += 1
        if st == _ESC:
            if b == 0x5B:  # [
                self._state = _CSI
            elif b == 0x5D:  # ]
                self._state, seq.osc = _STR, True
            elif b in (0x50, 0x58, 0x5E, 0x5F):  # P X ^ _
                self._state, seq.osc = _STR, False
            elif 0x20 <= b <= 0x2F:
                seq.inter.append(b)
                self._state = _ESC_INT
            else:
                self._state = _GROUND
                self._esc_final(b, base + i)
            return i + 1
        if st == _ESC_INT:
            if 0x20 <= b <= 0x2F:
                seq.inter.append(b)
                if seq.length > MAX_CSI:
                    self._state = _GROUND
            else:
                self._state = _GROUND  # Zeichensatz u. ä.: ignorieren
            return i + 1
        # _CSI
        if seq.length > MAX_CSI:
            self._state = _GROUND
            return i  # Rest als Text
        if 0x30 <= b <= 0x3F:
            if seq.inter:
                seq.ignore = True
            seq.params.append(b)
        elif 0x20 <= b <= 0x2F:
            seq.inter.append(b)
        else:  # 0x40..0x7E
            self._state = _GROUND
            if not seq.ignore:
                self._csi(bytes(seq.params), bytes(seq.inter), b, base + i + 1)
        return i + 1

    def _string(self, data: bytes, i: int, base: int) -> int:
        seq = self._seq
        if self._state == _STR_ESC:
            if data[i] == 0x5C:  # ESC \ = ST
                self._state = _GROUND
                return i + 1
            # ESC beendet die Zeichenkette und beginnt eine neue Sequenz
            self._seq = _Seq(start=base + i - 1)
            self._state = _ESC
            return i
        stop = (_STR_STOP_OSC if seq.osc else _STR_STOP_ST).search(data, i)
        end = stop.start() if stop is not None else len(data)
        room = MAX_STRING - seq.length
        if end - i > room:
            self._state = _GROUND  # zu lang: Rest ist Text
            return i + max(room, 0)
        seq.length += end - i
        if stop is None:
            return end
        b = data[end]
        if b == 0x1B:
            self._state = _STR_ESC
        else:
            self._state = _GROUND  # BEL, CAN, SUB
        return end + 1

    # --------------------------------------------------------------- Text
    def _text(self, run: bytes, off: int) -> None:
        if run.isascii():
            self._write(run.decode("ascii"), range(off, off + len(run)))
            return
        text = run.decode("utf-8")
        offs: list[int] = []
        o = off
        for ch in text:
            offs.append(o)
            cp = ord(ch)
            o += 1 if cp < 0x80 else 2 if cp < 0x800 else 3 if cp < 0x10000 else 4
        # C1-Steuerzeichen (U+0080..U+009F) werden nie dargestellt
        if any(0x80 <= ord(c) <= 0x9F for c in text):
            keep = [(c, x) for c, x in zip(text, offs, strict=True) if not 0x80 <= ord(c) <= 0x9F]
            text = "".join(c for c, _ in keep)
            offs = [x for _, x in keep]
        if text:
            self._write(text, offs)

    def _write(self, text: str, offs: Sequence[int]) -> None:
        row = self._rows[self._cur]
        attr = self._attr
        n = len(text)
        i = 0
        while i < n:
            col = self._col
            if col >= MAX_COLS:
                row.wrapped = True
                self._linefeed(offs[i] - 1)
                row = self._rows[self._cur]
                col = 0
            ln = len(row.chars)
            if col == ln:
                k = min(n - i, MAX_COLS - col)
                row.chars.extend(text[i : i + k])
                row.raws.extend(offs[i : i + k])
                row.attrs.extend([attr] * k)
                self._col = col + k
                i += k
                continue
            if col > ln:
                pad = col - ln
                row.chars.extend(" " * pad)
                row.raws.extend([offs[i]] * pad)
                row.attrs.extend([_DEFAULT] * pad)
                continue
            ch = text[i]
            old = row.chars[col]
            if old != ch and old != " ":
                row.overwritten = True
            row.chars[col] = ch
            row.raws[col] = offs[i]
            row.attrs[col] = attr
            self._col = col + 1
            i += 1
        if n:
            w = self._width
            self._wrap = bool(w) and self._col > 0 and self._col % w == 0
            self._last_char = text[-1]
            end = offs[-1] + 1
            if end > row.raw_end:
                row.raw_end = end

    # ------------------------------------------------------ Cursor-Modell
    def _cursor(self) -> int:
        """Index der Zelle, auf der der Cursor physisch steht."""
        return self._col - 1 if self._wrap else self._col

    def _row_start(self) -> int:
        """Index des Anfangs der physischen Zeile des Cursors in der logischen Zeile."""
        w = self._width
        if not w:
            return 0
        return (self._cursor() // w) * w

    def _row_end(self) -> int:
        w = self._width
        return self._row_start() + w if w else MAX_COLS

    def _set_col(self, col: int) -> None:
        self._col = max(0, min(col, MAX_COLS - 1))
        self._wrap = False

    def _phys_rows(self, row: _Row) -> int:
        w = self._width
        return max(1, -(-len(row.chars) // w)) if w else 1

    # ----------------------------------------------------------- Steuerung
    def _control(self, b: int, off: int) -> None:
        if b == 0x0A or b == 0x0B or b == 0x0C:
            self._linefeed(off)
        elif b == 0x0D:
            self._set_col(self._row_start())
        elif b == 0x08:
            cur = self._cursor()
            self._set_col(cur - 1 if cur > self._row_start() else cur)
        elif b == 0x09:
            start = self._row_start()
            col = self._cursor() - start
            nxt = (col // 8 + 1) * 8
            if self._width:
                nxt = min(nxt, self._width - 1)
            self._set_col(start + nxt)

    def _linefeed(self, off: int) -> None:
        row = self._rows[self._cur]
        if off + 1 > row.raw_end:
            row.raw_end = off + 1
        self._col = 0
        self._wrap = False
        if self._cur < len(self._rows) - 1:
            self._cur += 1
            return
        self._rows.append(_Row(off + 1, self._prompt))
        self._cur += 1
        while len(self._rows) > MAX_UP + 1:
            old = self._rows.pop(0)
            self._done.append(self._line(old, old.raw_end))
            self._base_row += 1
            self._cur -= 1

    def _up(self, n: int) -> None:
        w = self._width
        if not w:
            self._cur = max(0, self._cur - n)
            self._wrap = False
            return
        start = self._row_start()
        col = self._cursor() - start
        pr = start // w
        cur = self._cur
        while n > 0:
            if pr >= n:
                pr -= n
                break
            n -= pr + 1
            if cur == 0:
                pr = 0
                break
            cur -= 1
            pr = self._phys_rows(self._rows[cur]) - 1
        self._cur = cur
        self._set_col(pr * w + col)

    def _down(self, n: int) -> None:
        w = self._width
        if not w:
            self._cur = min(len(self._rows) - 1, self._cur + n)
            self._wrap = False
            return
        start = self._row_start()
        col = self._cursor() - start
        pr = start // w
        cur = self._cur
        last = len(self._rows) - 1
        while n > 0:
            rows_here = self._phys_rows(self._rows[cur])
            if pr + n < rows_here:
                pr += n
                break
            n -= rows_here - pr
            if cur == last:
                pr = rows_here - 1
                break
            cur += 1
            pr = 0
        self._cur = cur
        self._set_col(pr * w + col)

    def _touch(self, off: int) -> None:
        row = self._rows[self._cur]
        if off > row.raw_end:
            row.raw_end = off

    def _erase(self, row: _Row, start: int, end: int) -> None:
        """Zellen [start, end) leeren (Blanks), am Zeilenende kürzen."""
        start = max(0, start)
        end = min(end, len(row.chars))
        if start >= end:
            return
        if any(c != " " for c in row.chars[start:end]):
            row.overwritten = True
        if end == len(row.chars):
            del row.chars[start:], row.raws[start:], row.attrs[start:]
        else:
            for k in range(start, end):
                row.chars[k] = " "
                row.attrs[k] = _DEFAULT

    def _new_row_if_content(self, off: int) -> None:
        row = self._rows[-1]
        self._cur = len(self._rows) - 1
        if row.chars:
            self._linefeed(off)
        self._set_col(0)

    def _esc_final(self, b: int, off: int) -> None:
        if self._alt:
            return
        if b == 0x37:  # ESC 7
            self._saved = (self._base_row + self._cur, self._cursor(), self._attr)
        elif b == 0x38:  # ESC 8
            self._restore()
        elif b == 0x4D:  # ESC M (reverse index)
            self._up(1)
        elif b == 0x44:  # ESC D (index)
            self._linefeed(off)
        elif b == 0x45:  # ESC E (next line)
            self._linefeed(off)
        elif b == 0x63:  # ESC c (Reset)
            self._attr = _DEFAULT
            self._new_row_if_content(off)

    def _restore(self) -> None:
        if self._saved is None:
            return
        row_abs, col, attr = self._saved
        self._cur = min(max(0, row_abs - self._base_row), len(self._rows) - 1)
        self._set_col(col)
        self._attr = attr

    # ---------------------------------------------------------------- CSI
    def _csi(self, params: bytes, inter: bytes, final: int, end_off: int) -> None:
        private = params[:1] if params[:1] in (b"?", b"<", b"=", b">") else b""
        body = params[len(private) :]
        if private == b"?" and final in (0x68, 0x6C) and not inter:  # h / l
            modes = _ints(body)
            if any(m in (1049, 1047, 47) for m in modes):
                self._alt_mode(final == 0x68, end_off)
            return
        if self._alt or private or inter:
            return
        args = _ints(body)
        n = args[0] if args and args[0] else 1
        p0 = args[0] if args else 0
        f = chr(final)
        row = self._rows[self._cur]
        if f == "m":
            self._sgr(body)
        elif f == "K":
            cur = self._cursor()
            if p0 == 0:
                self._erase(row, cur, self._row_end())
            elif p0 == 1:
                self._erase(row, self._row_start(), cur + 1)
            elif p0 == 2:
                self._erase(row, self._row_start(), self._row_end())
            self._touch(end_off)
        elif f in "Ca":
            start = self._row_start()
            limit = start + self._width - 1 if self._width else MAX_COLS - 1
            self._set_col(min(self._cursor() + n, limit))
        elif f == "D":
            self._set_col(max(self._row_start(), self._cursor() - n))
        elif f in "G`":
            col = min(max(n, 1), self._width or MAX_COLS) - 1
            self._set_col(self._row_start() + col)
        elif f == "A":
            self._up(n)
        elif f in "Be":
            self._down(n)
        elif f == "E":
            self._down(n)
            self._set_col(self._row_start())
        elif f == "F":
            self._up(n)
            self._set_col(self._row_start())
        elif f in "Hf":
            self._new_row_if_content(end_off - 1)
            col = args[1] if len(args) > 1 and args[1] else 1
            self._set_col(min(col, self._width or MAX_COLS) - 1)
        elif f == "J":
            cur = self._cursor()
            if p0 == 0:
                self._erase(row, cur, len(row.chars))
                for r in self._rows[self._cur + 1 :]:
                    self._erase(r, 0, len(r.chars))
                self._touch(end_off)
            elif p0 == 1:
                self._erase(row, 0, cur + 1)
                for r in self._rows[: self._cur]:
                    self._erase(r, 0, len(r.chars))
            else:
                self._new_row_if_content(end_off - 1)
        elif f == "X":
            cur = self._cursor()
            self._erase(row, cur, min(cur + n, self._row_end()))
            self._touch(end_off)
        elif f == "P":
            cur = self._cursor()
            if cur < len(row.chars):
                k = min(n, len(row.chars) - cur)
                if any(c != " " for c in row.chars[cur : cur + k]):
                    row.overwritten = True
                del row.chars[cur : cur + k]
                del row.raws[cur : cur + k]
                del row.attrs[cur : cur + k]
            self._touch(end_off)
        elif f == "@":
            cur = self._cursor()
            if cur < len(row.chars):
                k = min(n, MAX_COLS - len(row.chars))
                row.chars[cur:cur] = [" "] * k
                row.raws[cur:cur] = [end_off - 1] * k
                row.attrs[cur:cur] = [_DEFAULT] * k
            self._touch(end_off)
        elif f == "b":
            if self._last_char is not None:
                k = min(n, MAX_COLS)
                self._write(self._last_char * k, [end_off - 1] * k)
        elif f == "s":
            self._saved = (self._base_row + self._cur, self._cursor(), self._attr)
        elif f == "u":
            self._restore()

    def _sgr(self, body: bytes) -> None:
        if not body:
            self._attr = _DEFAULT
            return
        groups = body.split(b";")[:32]
        a = self._attr
        fg, bg, bold, conceal, inverse = a.fg, a.bg, a.bold, a.conceal, a.inverse
        i = 0
        while i < len(groups):
            sub = [_int(x) for x in groups[i].split(b":")[:8]]
            code = sub[0] or 0
            if len(sub) > 1:  # Doppelpunkt-Form, z. B. 38:2::r:g:b
                if code in (38, 48):
                    col = _color(sub[1:])
                    if code == 38:
                        fg = col
                    else:
                        bg = col
                i += 1
                continue
            if code == 0:
                fg, bg, bold, conceal, inverse = None, None, False, False, False
            elif code == 1:
                bold = True
            elif code == 22:
                bold = False
            elif code == 7:
                inverse = True
            elif code == 27:
                inverse = False
            elif code == 8:
                conceal = True
            elif code == 28:
                conceal = False
            elif 30 <= code <= 37:
                fg = _BASE[code - 30]
            elif code == 39:
                fg = None
            elif 40 <= code <= 47:
                bg = _BASE[code - 40]
            elif code == 49:
                bg = None
            elif 90 <= code <= 97:
                fg = "bright_" + _BASE[code - 90]
            elif 100 <= code <= 107:
                bg = "bright_" + _BASE[code - 100]
            elif code in (38, 48):
                kind = _int(groups[i + 1]) if i + 1 < len(groups) else None
                if kind == 5:
                    col = _palette(_int(groups[i + 2]) or 0) if i + 2 < len(groups) else None
                    i += 2
                elif kind == 2:
                    rgb = [_int(groups[i + k]) if i + k < len(groups) else None for k in (2, 3, 4)]
                    col = _rgb(rgb)
                    i += 4
                else:
                    col = None
                    i += 1
                if code == 38:
                    fg = col
                else:
                    bg = col
            i += 1
        self._attr = _Attr(fg, bg, bold, conceal, inverse)

    # ---------------------------------------------------- Alternate Screen
    def _alt_mode(self, on: bool, end_off: int) -> None:
        if on and not self._alt:
            self._flush_rows(self._seq.start)
            self._alt = True
            self._alt_start = self._seq.start
            self._alt_content = end_off
            self._alt_buf = bytearray()
            self._alt_dropped = 0
            self._alt_from = end_off - self._buf_base
        elif not on and self._alt:
            self._alt_append(self._buf[self._alt_from : end_off - self._buf_base])
            keep = self._seq.start - self._alt_content - self._alt_dropped
            if keep >= 0:
                del self._alt_buf[keep:]
            self._alt_close(end_off)

    def _alt_append(self, chunk: bytes) -> None:
        self._alt_buf += chunk
        extra = len(self._alt_buf) - MAX_ALT_BYTES
        if extra > 0:
            del self._alt_buf[:extra]
            self._alt_dropped += extra

    def _alt_close(self, end_off: int) -> None:
        self._alt = False
        rows = _render_screen(bytes(self._alt_buf), self._height, self._width or 80)
        flags = FLAG_ALTSCREEN | (FLAG_PROMPT if self._prompt else 0)
        for text in rows:
            self._done.append(NormLine(text, self._alt_start, end_off, (), flags, ()))
        self._alt_buf = bytearray()
        self._reset_window(end_off)

    # ------------------------------------------------------------ Ausgabe
    def _flush_utf8(self) -> None:
        if self._pend:
            off = self._pend_off
            self._pend = b""
            if self._state == _GROUND and not self._alt:
                self._write("�", (off,))

    def _line(self, row: _Row, raw_end: int) -> NormLine:
        chars, raws, attrs = row.chars, row.raws, row.attrs
        n = len(chars)
        while n and chars[n - 1] == " ":
            n -= 1
        runs: list[list] = []  # [start, end, visual]
        i = 0
        while i < n:
            a = attrs[i]
            j = i + 1
            while j < n and (attrs[j] is a or attrs[j] == a):
                j += 1
            v = a.visual
            if runs and runs[-1][2] == v:
                runs[-1][1] = j
            else:
                runs.append([i, j, v])
            i = j
        spans: list[SgrSpan] = []
        concealed = False
        for s, e, v in runs:
            if v != _PLAIN:
                spans.append(SgrSpan(s, e, v[0], v[1], v[2], v[3]))
                if v[3] and any(ch != " " for ch in chars[s:e]):
                    concealed = True
        flags = (
            (FLAG_PROMPT if row.prompt else 0)
            | (FLAG_CONCEALED if concealed else 0)
            | (FLAG_OVERWRITTEN if row.overwritten else 0)
            | (FLAG_WRAPPED if row.wrapped else 0)
        )
        return NormLine("".join(chars[:n]), row.raw_start, max(raw_end, row.raw_start), tuple(spans),
                        flags, _compress(raws[:n], row.raw_start))


# --------------------------------------------------------------------------- Helfer


def _int(raw: bytes | None) -> int | None:
    if not raw or not raw.isdigit():
        return None
    if len(raw) > 6:
        return MAX_PARAM
    return min(int(raw), MAX_PARAM)


def _ints(body: bytes) -> list[int]:
    out: list[int] = []
    for part in body.split(b";")[:32]:
        v = _int(part.split(b":", 1)[0])
        out.append(v if v is not None else 0)
    return out


def _rgb(vals: Sequence[int | None]) -> str | None:
    if len(vals) != 3 or any(v is None or v > 255 for v in vals):
        return None
    r, g, b = (int(v or 0) for v in vals)
    return f"#{r:02x}{g:02x}{b:02x}"


def _color(sub: Sequence[int | None]) -> str | None:
    """Farbe aus Doppelpunkt-Unterparametern nach 38/48."""
    if not sub:
        return None
    if sub[0] == 5 and len(sub) > 1:
        return _palette(sub[1] or 0)
    if sub[0] == 2:
        rest = list(sub[1:])
        if len(rest) == 4:  # Farbraum-ID vorne
            rest = rest[1:]
        return _rgb(rest)
    return None


def _utf8_subpart(data: bytes, i: int) -> tuple[int, bool]:
    """Länge des maximalen Teilstücks ab ``i`` und ob es am Puffer-Ende abgeschnitten ist."""
    ranges = _UTF8_RANGES.get(data[i])
    if ranges is None:
        return 1, False
    k = 1
    for lo, hi in ranges:
        if i + k >= len(data):
            return k, True
        if not lo <= data[i + k] <= hi:
            return k, False
        k += 1
    return k, False


_PARAM_CLAMP = re.compile(rb"\d{4,}")
# Sequenzen, an denen pyte scheitert oder die nichts zum Bild beitragen:
# CSI mit privatem Präfix < = > oder Zwischenzeichen, DCS/SOS/PM/APC und OSC.
_PYTE_DROP = re.compile(
    rb"\x1b\[[<=>][0-?]*[ -/]*[@-~]"
    rb"|\x1b\[[0-?]*[ -/]+[@-~]"
    rb"|\x1b[P_^X][^\x1b]*(?:\x1b\\)?"
    rb"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
)
_ESC_SPLIT = re.compile(rb"(?=\x1b)")
_CLEAR = re.compile(rb"\x1b\[[02]?J")


def _render_screen(data: bytes, rows: int, cols: int) -> list[str]:
    """Schlussbild des Alternate Screens über pyte (ohne Leerzeilen am Rand).

    pyte ist nicht für feindliche Eingaben gebaut: Parameter werden begrenzt,
    problematische Sequenzen entfernt, und nach einer Ausnahme läuft ein neuer
    Parser auf demselben Bild weiter. Gerendert wird ab dem letzten
    Bildschirm-Löschen, das spart Zeit bei langen Sitzungen.
    """
    if not data:
        return []
    try:
        import pyte
    except ImportError:  # pragma: no cover - pyte ist Abhängigkeit
        return []
    last_clear = None
    for m in _CLEAR.finditer(data):
        last_clear = m.start()
    if last_clear is not None and last_clear > 0:
        data = b"\x1b[H" + data[last_clear:]
    data = _PYTE_DROP.sub(b"", _PARAM_CLAMP.sub(b"999", data))
    screen = pyte.Screen(max(1, cols), max(1, rows))
    stream = pyte.ByteStream(screen)
    for part in _ESC_SPLIT.split(data):
        if not part:
            continue
        try:
            stream.feed(part)
        except Exception:  # noqa: BLE001 - feindliche Bytes dürfen pyte nicht durchschlagen
            stream = pyte.ByteStream(screen)
    lines = [ln.rstrip() for ln in screen.display]
    while lines and not lines[-1]:
        lines.pop()
    while lines and not lines[0]:
        lines.pop(0)
    return lines


def normalize(data: bytes, start: int = 0, *, prompt_ranges: Iterable[tuple[int, int | None]] = (),
              breaks: Iterable[int] = (), cols: int = 0, rows: int = 24) -> list[NormLine]:
    """Normalisiert einen zusammenhängenden Stream-Bereich in einem Schritt.

    ``prompt_ranges`` sind Bereiche ``[a, c)`` (``c=None``: bis zum Ende), deren
    Zeilen ``prompt_echo`` tragen; ``breaks`` weitere Grenzen.
    """
    marks: dict[int, bool | None] = {}
    for b in breaks:
        marks.setdefault(b, None)
    for a, c in prompt_ranges:
        marks[a] = True
        if c is not None:
            marks[c] = False
    norm = Normalizer(start, cols=cols, rows=rows, prompt=marks.pop(start, None) is True)
    pos = start
    for off in sorted(o for o in marks if start < o <= start + len(data)):
        norm.feed(data[pos - start : off - start])
        norm.boundary(off, prompt=marks[off])
        pos = off
    norm.feed(data[pos - start :])
    return norm.finish()
