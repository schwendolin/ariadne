"""Einheiten: was ein Parser auf einmal liest (Architektur 2, 5.4, 5.6).

:class:`Unit` implementiert ``ariadne.parsers.api.UnitView`` für Befehle,
Remote-Segmente und Dateien. Sie ist unveränderlich und lässt sich für den
Worker als JSON serialisieren (:meth:`Unit.to_dict`, :meth:`Unit.from_dict`).

Zeilen: ``all_lines`` enthält alles in Anzeige-Reihenfolge, ``lines`` nur die
für Parser sichtbaren Zeilen (ohne ``prompt_echo`` und ohne Schlussbild des
Alternate Screens). ``Span.line_start`` eines Parsers zählt in ``lines``; in
``unit_line`` steht dieser Index in der Spalte ``idx`` (siehe ``schema_units``).
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ariadne.ingest.normalizer import (
    FLAG_ALTSCREEN,
    FLAG_CONCEALED,
    FLAG_OVERWRITTEN,
    FLAG_PROMPT,
    FLAG_WRAPPED,
    NormLine,
    normalize,
)
from ariadne.parsers.api import Line, SgrSpan, UnitKind

__all__ = [
    "Unit",
    "line_flags",
    "line_visible",
    "file_lines",
    "is_binary",
    "MAX_FILE_LINES_BYTES",
    "MAX_LINE",
]

MAX_FILE_LINES_BYTES = 16 << 20  # grössere Textdateien: nur open_bytes(), keine Zeilen
MAX_LINE = 16384
_KINDS = ("command", "segment", "file", "image")


def line_flags(line: Line, extra: int = 0) -> int:
    """Flag-Bits einer Zeile (wie ``NormLine.flags``)."""
    return (
        (FLAG_PROMPT if line.prompt_echo else 0)
        | (FLAG_CONCEALED if line.concealed else 0)
        | (FLAG_OVERWRITTEN if line.overwritten else 0)
        | extra
    )


def line_visible(flags: int) -> bool:
    """Sieht ein Parser diese Zeile? Nie bei Prompt-Echo und Alternate Screen."""
    return not flags & (FLAG_PROMPT | FLAG_ALTSCREEN)


def _freeze(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return MappingProxyType({str(k): _freeze(v) for k, v in obj.items()})
    if isinstance(obj, list | tuple):
        return tuple(_freeze(v) for v in obj)
    return obj


def _thaw(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {k: _thaw(v) for k, v in obj.items()}
    if isinstance(obj, tuple):
        return [_thaw(v) for v in obj]
    return obj


@dataclass(frozen=True)
class Unit:
    """Nur lesbare Einheit (``UnitView``) mit Zusatzangaben für Pipeline und Belegansicht."""

    unit_id: str
    kind: UnitKind
    ts_utc_ns: int
    argv: tuple[str, ...] = ()
    cmd_text: str | None = None
    exit_code: int | None = None
    cwd: str | None = None
    context: Mapping[str, Any] = field(default_factory=dict)
    all_lines: tuple[Line, ...] = ()
    all_flags: tuple[int, ...] = ()  # Flag-Bits je Zeile in all_lines
    path: str | None = None
    mime: str | None = None
    sniff: str | None = None
    # Zusatzangaben (nicht Teil von UnitView)
    terminal_id: str | None = None
    cmd_id: str | None = None
    span_id: str | None = None
    start_off: int | None = None
    end_off: int | None = None
    ts_end_ns: int | None = None
    blob_id: str | None = None
    sha256: str | None = None
    size: int | None = None
    flags: tuple[str, ...] = ()  # partial, truncated, gap, altscreen, binary, too_large
    state: str = "final"  # open | provisional | final
    data: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.kind not in _KINDS:
            raise ValueError(f"unbekannte Einheit: {self.kind!r}")
        object.__setattr__(self, "argv", tuple(str(a) for a in self.argv))
        object.__setattr__(self, "context", _freeze(dict(self.context)))
        object.__setattr__(self, "all_lines", tuple(self.all_lines))
        object.__setattr__(self, "flags", tuple(self.flags))
        flags = tuple(self.all_flags)
        if len(flags) != len(self.all_lines):
            flags = tuple(line_flags(ln) for ln in self.all_lines)
        object.__setattr__(self, "all_flags", flags)
        vis = tuple(i for i, f in enumerate(flags) if line_visible(f))
        object.__setattr__(self, "_visible", vis)
        object.__setattr__(self, "_lines", tuple(self.all_lines[i] for i in vis))

    # ---- UnitView ------------------------------------------------------- #
    @property
    def lines(self) -> Sequence[Line]:  # type: ignore[override]
        """Für Parser sichtbare Zeilen (ohne Prompt-Echo, ohne Alternate Screen)."""
        return self._lines  # type: ignore[attr-defined, no-any-return]

    def open_bytes(self) -> bytes:
        """Rohbytes: bei Dateien der Inhalt, bei Strom-Einheiten leer."""
        return self.data or b""

    # ---- Hilfen ---------------------------------------------------------- #
    @property
    def visible_positions(self) -> tuple[int, ...]:
        """Position in ``all_lines`` für jeden Index in ``lines``."""
        return self._visible  # type: ignore[attr-defined, no-any-return]

    def line_range(self, line_start: int, line_end: int) -> tuple[int, int] | None:
        """Roh-Bereich ``[a, b)`` der sichtbaren Zeilen ``line_start..line_end`` (inklusiv)."""
        lines = self.lines
        if not lines or line_start < 0 or line_end < line_start or line_end >= len(lines):
            return None
        return lines[line_start].raw_start, max(ln.raw_end for ln in lines[line_start : line_end + 1])

    # ---- Serialisierung -------------------------------------------------- #
    def to_dict(self, *, include_hidden: bool = False, include_data: bool = True) -> dict[str, Any]:
        """JSON-taugliches Dict. Ohne ``include_hidden`` fehlen Prompt-Echo und
        Alternate Screen; so verlassen sie nie den Daemon in Richtung Parser."""
        if include_hidden:
            pairs = list(zip(self.all_lines, self.all_flags, strict=True))
        else:
            pairs = [(self.all_lines[i], self.all_flags[i]) for i in self.visible_positions]
        d: dict[str, Any] = {
            "unit_id": self.unit_id,
            "kind": self.kind,
            "ts_utc_ns": self.ts_utc_ns,
            "argv": list(self.argv),
            "cmd_text": self.cmd_text,
            "exit_code": self.exit_code,
            "cwd": self.cwd,
            "context": _thaw(self.context),
            "lines": [_line_to_dict(ln, f) for ln, f in pairs],
            "path": self.path,
            "mime": self.mime,
            "sniff": self.sniff,
            "terminal_id": self.terminal_id,
            "cmd_id": self.cmd_id,
            "span_id": self.span_id,
            "start_off": self.start_off,
            "end_off": self.end_off,
            "ts_end_ns": self.ts_end_ns,
            "blob_id": self.blob_id,
            "sha256": self.sha256,
            "size": self.size,
            "flags": list(self.flags),
            "state": self.state,
        }
        if include_data and self.data is not None:
            d["data"] = base64.b64encode(self.data).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Unit:
        lines: list[Line] = []
        flags: list[int] = []
        for raw in d.get("lines") or ():
            ln, f = _line_from_dict(raw)
            lines.append(ln)
            flags.append(f)
        data = d.get("data")
        return cls(
            unit_id=str(d["unit_id"]),
            kind=d["kind"],
            ts_utc_ns=int(d.get("ts_utc_ns") or 0),
            argv=tuple(str(a) for a in d.get("argv") or ()),
            cmd_text=_opt_str(d.get("cmd_text")),
            exit_code=_opt_int(d.get("exit_code")),
            cwd=_opt_str(d.get("cwd")),
            context=dict(d.get("context") or {}),
            all_lines=tuple(lines),
            all_flags=tuple(flags),
            path=_opt_str(d.get("path")),
            mime=_opt_str(d.get("mime")),
            sniff=_opt_str(d.get("sniff")),
            terminal_id=_opt_str(d.get("terminal_id")),
            cmd_id=_opt_str(d.get("cmd_id")),
            span_id=_opt_str(d.get("span_id")),
            start_off=_opt_int(d.get("start_off")),
            end_off=_opt_int(d.get("end_off")),
            ts_end_ns=_opt_int(d.get("ts_end_ns")),
            blob_id=_opt_str(d.get("blob_id")),
            sha256=_opt_str(d.get("sha256")),
            size=_opt_int(d.get("size")),
            flags=tuple(str(x) for x in d.get("flags") or ()),
            state=str(d.get("state") or "final"),
            data=base64.b64decode(data) if isinstance(data, str) else None,
        )


def _opt_str(v: Any) -> str | None:
    return None if v is None else str(v)


def _opt_int(v: Any) -> int | None:
    if v is None or isinstance(v, bool):
        return None
    return int(v)


def _line_to_dict(ln: Line, flags: int) -> dict[str, Any]:
    d: dict[str, Any] = {"t": ln.text, "s": ln.raw_start, "e": ln.raw_end, "f": flags}
    if ln.sgr:
        d["g"] = [[s.col_start, s.col_end, s.fg, s.bg, int(s.bold), int(s.concealed)] for s in ln.sgr]
    return d


def _line_from_dict(d: Mapping[str, Any]) -> tuple[Line, int]:
    flags = int(d.get("f") or 0)
    sgr = tuple(
        SgrSpan(int(g[0]), int(g[1]), g[2], g[3], bool(g[4]), bool(g[5])) for g in d.get("g") or ()
    )
    line = Line(str(d["t"]), int(d["s"]), int(d["e"]), sgr, bool(flags & FLAG_PROMPT),
                bool(flags & FLAG_CONCEALED), bool(flags & FLAG_OVERWRITTEN))
    return line, flags


# --------------------------------------------------------------------------- Dateien


def is_binary(data: bytes) -> bool:
    """Grobe Erkennung: NUL-Bytes oder kein UTF-8 im Anfang der Datei."""
    head = data[:8192]
    if b"\x00" in head:
        return True
    try:
        head.decode("utf-8")
    except UnicodeDecodeError as exc:
        return exc.start < len(head) - 3  # am Ende abgeschnittenes Zeichen ist kein Hinweis
    return False


def file_lines(data: bytes) -> list[NormLine] | None:
    """Zeilen einer Textdatei mit Byte-Offsets in der Datei; ``None`` bei Binärdateien.

    Enthält die Datei Escape-Sequenzen (z. B. ``linpeas | tee``), läuft sie durch
    den Terminal-Normalizer, sonst wird schlicht an ``\\n`` getrennt (Tabs bleiben).
    """
    if is_binary(data) or len(data) > MAX_FILE_LINES_BYTES:
        return None
    if b"\x1b" in data:
        return normalize(data, 0)
    out: list[NormLine] = []
    pos = 0
    n = len(data)
    while pos < n:
        nl = data.find(b"\n", pos)
        end = n if nl < 0 else nl + 1
        body = data[pos : end - 1 if nl >= 0 else end]
        if body.endswith(b"\r"):
            body = body[:-1]
        text = body.decode("utf-8", "replace")
        if len(text) <= MAX_LINE:
            out.append(NormLine(text, pos, end, (), 0, ()))
        else:
            for k in range(0, len(text), MAX_LINE):
                out.append(NormLine(text[k : k + MAX_LINE], pos, end, (), FLAG_WRAPPED, ()))
        pos = end
    return out
