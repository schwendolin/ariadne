"""Hilfen für die Ingest-Tests: synthetische Terminal-Ereignisse, Stub-Parser, Stub-Projector."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, ClassVar

from ariadne.parsers.api import Mention, Obs, Ref, Span

TID = "t-0001-aaaa-bbbb"
BASE_TS = 1_790_000_000_000_000_000  # 2026-09
SEC = 1_000_000_000


class TermSim:
    """Erzeugt Journal-Einträge wie Daemon und Shim (Offsets, Marker, Entscheide)."""

    def __init__(self, journal: Any, tid: str = TID, *, cols: int = 80, rows: int = 24,
                 ts: int = BASE_TS) -> None:
        self.j = journal
        self.tid = tid
        self.off = 0
        self.counter = 0
        self.ts = ts
        self.cols = cols
        self.rows = rows

    def tick(self, seconds: float = 1.0) -> int:
        self.ts += int(seconds * SEC)
        return self.ts

    def _append(self, kind: str, header: dict[str, Any], body: bytes | None = None, origin: str = "shim",
                stream_off: int | None = None) -> Any:
        header = {"terminal_id": self.tid, **header}
        return self.j.append(kind, header, body, origin=origin, terminal_id=self.tid,
                             stream_off=stream_off, ts_utc_ns=self.tick(0.01))

    def open(self, stack: list[dict[str, Any]] | None = None) -> None:
        self._append("term.open", {"shell": "zsh", "rows": self.rows, "cols": self.cols, "shim_version": "1"},
                     origin="daemon", stream_off=self.off)
        self._append("term.bind", {"project_id": "p1"}, origin="daemon", stream_off=self.off)
        self.snapshot(stack)

    def snapshot(self, stack: list[dict[str, Any]] | None = None) -> None:
        stack = stack or [{"kind": "local", "host": "local", "opened_at": 0}]
        self._append("term.ctx_snapshot", {"stream_off": self.off, "stack": stack}, origin="daemon",
                     stream_off=self.off)

    def out(self, data: bytes, *, chunk: int | None = None) -> None:
        step = chunk or max(1, len(data))
        for i in range(0, len(data), step):
            part = data[i : i + step]
            self._append("term.out", {"stream_off": self.off, "length": len(part), "t_shim_ns": self.ts},
                         part, stream_off=self.off)
            self.off += len(part)

    def mark(self, mark: str, *, fg: bool = True, **fields: Any) -> None:
        self.counter += 1
        h = {"stream_off": self.off, "mark": mark, "counter": self.counter, "fg_shell": fg, "shell_pid": 4242}
        h.update({k: v for k, v in fields.items() if v is not None})
        self._append("term.mark", h, stream_off=self.off)

    def prompt(self, typed: str = "", prompt: bytes = b"\x1b[32mkali@kali\x1b[0m:~$ ") -> None:
        self.out(b"\x1b]133;A\x07")
        self.mark("A", cwd="/home/kali")
        self.out(prompt + typed.encode() + b"\r\n")

    def command(self, cmd: str, output: bytes, *, exit: int = 0, cwd: str = "/home/kali",
                text_in_d: bool = False) -> int:
        """Prompt, C, Ausgabe, D. Gibt den C-Offset zurück."""
        self.prompt(cmd)
        self.out(b"\x1b]133;C\x07")
        c = self.off
        if text_in_d:
            self.mark("C", cwd=cwd, user="kali")
        else:
            self.mark("C", cmd_typed=cmd, cwd=cwd, user="kali")
        self.out(output)
        self.out(b"\x1b]133;D;%d\x07" % exit)
        self.mark("D", exit=exit, cwd=cwd, cmd_typed=cmd if text_in_d else None)
        return c

    def start(self, cmd: str, output: bytes = b"") -> int:
        """Prompt und C ohne D (Befehl läuft noch)."""
        self.prompt(cmd)
        c = self.off
        self.mark("C", cmd_typed=cmd, cwd="/home/kali", user="kali")
        if output:
            self.out(output)
        return c

    def end(self, exit: int = 0, *, fg: bool = True) -> None:
        self.mark("D", fg=fg, exit=exit, cwd="/home/kali")

    def decision(self, event_kind: str, **header: Any) -> None:
        if event_kind == "d.ctx.set":
            header.setdefault("from_off", self.off)
        else:
            header.setdefault("stream_off", self.off)
        self._append(event_kind, {k: v for k, v in header.items() if v is not None}, origin="webui",
                     stream_off=header.get("stream_off", header.get("from_off")))

    def gap(self, lost: int, reason: str = "rec_off") -> None:
        self._append("term.gap", {"stream_off": self.off, "reason": reason, "bytes_lost": lost},
                     origin="daemon", stream_off=self.off)
        self.off += lost

    def close(self) -> None:
        self._append("term.close", {"stream_off": self.off, "exit_code": 0}, stream_off=self.off)


class StubParser:
    """Findet IPs der Form 10.10.10.x in sichtbaren Zeilen (Mention) und ``open``-Zeilen (Obs)."""

    id: ClassVar[str] = "stub.ip"
    version: ClassVar[str] = "1"
    trust: ClassVar[str] = "tool_text"
    auto_eligible: ClassVar[bool] = True

    def match(self, unit: Any) -> int:
        return 10 if unit.lines else 0

    def parse(self, unit: Any) -> Iterator[Obs | Mention]:
        import re

        for i, line in enumerate(unit.lines):
            for m in re.finditer(r"10\.10\.10\.\d+", line.text):
                yield Mention("ip", m.group(), Span(i, i, m.start(), m.end()))
            m = re.match(r"(\d+)/tcp\s+open", line.text)
            if m:
                yield Obs(Ref.service(Ref.ctx_host(), "tcp", int(m.group(1))), "service.state", "open",
                          Span(i, i))

    def companions(self, argv: Any, cwd: str) -> list[str]:
        return []


class StubHighParser(StubParser):
    id: ClassVar[str] = "stub.high"
    trust: ClassVar[str] = "structured"
    auto_eligible: ClassVar[bool] = False

    def match(self, unit: Any) -> int:
        return 50 if unit.kind == "command" and list(unit.argv[:1]) == ["nmap"] else 0

    def parse(self, unit: Any) -> Iterator[Obs | Mention]:
        yield Obs(Ref.ip("10.10.10.3"), "host.state", "up", Span(0, 0))


class StubProjector:
    """Merkt sich alle Aufrufe. Gleiche Signatur wie ``ariadne.ingest.projection.Projector``."""

    def __init__(self, conn: Any = None, *, project_key: bytes = b"", scope: Any = None,
                 profile: str = "lab") -> None:
        self.conn = conn
        self.calls: list[tuple[str, Any]] = []
        self.applied: dict[tuple[str, str], Any] = {}
        self.generation = 0

    def apply_unit(self, unit: Any, *, parser_id: str, parser_version: str, trust: str, auto_eligible: bool,
                   journal_seq: int, items: list[Any]) -> None:
        self.calls.append(("apply_unit", (unit.unit_id, parser_id, len(items))))
        self.applied[(unit.unit_id, parser_id)] = (unit, list(items), journal_seq, trust, auto_eligible)

    def clear_unit(self, unit_id: str) -> None:
        self.calls.append(("clear_unit", unit_id))
        for key in [k for k in self.applied if k[0] == unit_id]:
            del self.applied[key]

    def apply_decision(self, rec: Any) -> None:
        self.calls.append(("apply_decision", rec.kind))

    def rebuild(self) -> int:
        self.generation += 1
        self.calls.append(("rebuild", self.generation))
        return self.generation
