"""Einfache Einheiten für Parser- und Projektionstests (ohne Pipeline)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ariadne.ctxrules import split_command
from ariadne.parsers.api import Line, Mention, Obs, UnitKind

__all__ = ["FakeUnit", "make_unit", "make_lines", "run_parser", "item_dicts"]


@dataclass
class FakeUnit:
    """Implementiert ``ariadne.parsers.api.UnitView`` plus ``terminal_id``."""

    unit_id: str
    kind: UnitKind
    argv: Sequence[str]
    cmd_text: str | None
    exit_code: int | None
    cwd: str | None
    context: Mapping[str, Any]
    lines: Sequence[Line]
    path: str | None
    mime: str | None
    sniff: str | None
    ts_utc_ns: int
    terminal_id: str | None = None
    data: bytes = b""
    extra: dict[str, Any] = field(default_factory=dict)

    def open_bytes(self) -> bytes:
        return self.data


def make_lines(text: str, *, start: int = 0, flags: Mapping[int, str] | None = None) -> list[Line]:
    """Zeilen mit fortlaufenden Roh-Offsets; ``flags`` setzt prompt_echo/concealed/overwritten."""
    out: list[Line] = []
    off = start
    parts = text.split("\n")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    for i, t in enumerate(parts):
        raw = len(t.encode()) + 1
        f = (flags or {}).get(i, "")
        out.append(
            Line(
                t,
                off,
                off + raw,
                prompt_echo=f == "prompt_echo",
                concealed=f == "concealed",
                overwritten=f == "overwritten",
            )
        )
        off += raw
    return out


def make_unit(
    text: str = "",
    *,
    kind: UnitKind = "command",
    cmd: str | None = None,
    argv: Sequence[str] | None = None,
    unit_id: str = "u1",
    terminal_id: str | None = "t1",
    context: Mapping[str, Any] | None = None,
    path: str | None = None,
    data: bytes | None = None,
    mime: str | None = None,
    sniff: str | None = None,
    cwd: str | None = "/home/kali/lab",
    ts: int = 1_000_000_000,
    exit_code: int | None = 0,
    start: int = 0,
    flags: Mapping[int, str] | None = None,
) -> FakeUnit:
    if data is not None and not text:
        text = data.decode("utf-8", "replace")
    if argv is None:
        argv = split_command(cmd) if cmd else []
    ctx = (
        dict(context)
        if context is not None
        else ({"kind": "local", "host": "local", "opened_at": 0} if kind == "command" else {})
    )
    if terminal_id and "terminal_id" not in ctx and kind != "file":
        ctx["terminal_id"] = terminal_id
    return FakeUnit(
        unit_id=unit_id,
        kind=kind,
        argv=list(argv),
        cmd_text=cmd,
        exit_code=exit_code,
        cwd=cwd,
        context=ctx,
        lines=make_lines(text, start=start, flags=flags),
        path=path,
        mime=mime,
        sniff=sniff,
        ts_utc_ns=ts,
        terminal_id=terminal_id if kind != "file" else None,
        data=data if data is not None else b"",
    )


def run_parser(parser: Any, unit: FakeUnit) -> list[Obs | Mention]:
    return list(parser.parse(unit))


def item_dicts(items: Sequence[Obs | Mention]) -> list[dict[str, Any]]:
    out = []
    for it in items:
        d = it.to_dict()
        d["type"] = "obs" if isinstance(it, Obs) else "mention"
        out.append(d)
    return out
