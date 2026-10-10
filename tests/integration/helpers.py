"""Hilfen: ein simuliertes Terminal über den Fake-Shim und Fixture-Daten aus den Goldens."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tests.core.fakeshim import FakeShim

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "tests" / "golden"
TARGET = "10.10.10.3"
LHOST = "10.10.14.5"


def ms2(name: str) -> bytes:
    """Golden-Ausgabe des Metasploitable2-Falls, umgeschrieben auf das Lab-Ziel ``10.10.10.3``."""
    src = {"xml": GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml",
           "text": GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt"}[name]
    data = src.read_bytes()
    for a, b in ((b"192.168.56.101", TARGET.encode()), (b"192.168.56.102", LHOST.encode()),
                 (b"-sV -sC -oA scans/ms2", b"-sV -oA scans/lame"), (b"scans/ms2", b"scans/lame")):
        data = data.replace(a, b)
    return data


class Term:
    """Schreibt Rahmen wie ein Shim: fortlaufende ``seq``, Offsets, gültige Marker."""

    def __init__(self, shim: FakeShim) -> None:
        self.shim = shim
        self.seq = 0
        self.off = 0
        self.ctr = 0

    async def out(self, data: bytes) -> None:
        self.seq += 1
        await self.shim.out(self.seq, self.off, data)
        self.off += len(data)

    async def mark(self, mark: str, *, fg_shell: bool = True, **fields: Any) -> None:
        self.seq += 1
        self.ctr += 1
        await self.shim.event(self.seq, "term.mark", stream_off=self.off, mark=mark, counter=self.ctr,
                              fg_shell=fg_shell, **{k: v for k, v in fields.items() if v is not None})

    async def request(self, kind: str, **fields: Any) -> None:
        self.seq += 1
        await self.shim.event(self.seq, kind, **fields)

    async def command(self, cmd: str, output: bytes, *, cwd: str, exit: int = 0, end: bool = True) -> None:
        await self.mark("A", cwd=cwd)
        await self.out(b"$ " + cmd.encode() + b"\r\n")
        await self.mark("C", cmd_typed=cmd, cwd=cwd, user="kali")
        await self.out(output)
        if end:
            await self.mark("D", exit=exit, pipestatus=[exit], cwd=cwd)

    async def acked(self) -> None:
        await self.shim.wait_ack(self.seq, timeout=10)
