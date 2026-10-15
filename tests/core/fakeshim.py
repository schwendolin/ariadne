"""Fake-Shim für Daemon-Tests: spricht das Rahmenprotokoll über einen echten Unix-Socket."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from ariadne._shim import protocol as P
from ariadne.ids import new_id


class FakeShim:
    def __init__(self, sock: Path, terminal_id: str | None = None) -> None:
        self.sock = sock
        self.terminal_id = terminal_id or new_id()
        self.states: list[dict[str, Any]] = []
        self.acked = 0
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task[None] | None = None
        self._changed = asyncio.Event()
        self.closed = False

    async def connect(self, **hello: Any) -> FakeShim:
        self._reader, self._writer = await asyncio.open_unix_connection(str(self.sock))
        msg = {"proto": 1, "terminal_id": self.terminal_id, "tty": "/dev/pts/7", "shell": "zsh",
               "term": "xterm-256color", "rows": 40, "cols": 120, "shim_version": "test", "pid": 4242,
               "resume_from_seq": None}
        msg.update(hello)
        self._writer.write(P.encode_json(P.HELLO, msg))
        await self._writer.drain()
        self._task = asyncio.ensure_future(self._read_loop())
        return self

    async def _read_loop(self) -> None:
        dec = P.FrameDecoder()
        assert self._reader is not None
        try:
            while True:
                data = await self._reader.read(65536)
                if not data:
                    break
                for fr in dec.feed(data):
                    obj = P.decode_json(fr.payload)
                    if fr.type == P.STATE:
                        self.states.append(obj)
                    elif fr.type == P.ACK:
                        self.acked = max(self.acked, int(obj["seq"]))
                self._changed.set()
        finally:
            self.closed = True
            self._changed.set()

    async def _wait(self, pred: Any, timeout: float) -> Any:
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while True:
            res = pred()
            if res:
                return res
            remaining = end - loop.time()
            if remaining <= 0:
                raise TimeoutError("Bedingung nicht erfüllt")
            self._changed.clear()
            try:
                await asyncio.wait_for(self._changed.wait(), remaining)
            except TimeoutError:
                pass

    @property
    def state(self) -> dict[str, Any]:
        return self.states[-1] if self.states else {}

    async def wait_state(self, timeout: float = 5.0, **match: Any) -> dict[str, Any]:
        def pred() -> dict[str, Any] | None:
            st = self.state
            return st if st and all(st.get(k) == v for k, v in match.items()) else None
        return await self._wait(pred, timeout)

    async def wait_ack(self, seq: int, timeout: float = 5.0) -> int:
        return await self._wait(lambda: self.acked if self.acked >= seq else None, timeout)

    async def send(self, frame: bytes) -> None:
        assert self._writer is not None
        self._writer.write(frame)
        await self._writer.drain()

    async def out(self, seq: int, off: int, data: bytes, *, wall: int | None = None,
                  mono: int | None = None) -> None:
        """OUT (v1) mit der Zeit jetzt (Wanduhr und monotone Uhr wie ein echter Shim)."""
        await self.send(P.encode_out(seq, off, time.time_ns() if wall is None else wall,
                                     time.monotonic_ns() if mono is None else mono, data))

    async def outx(self, seq: int, off: int, data: bytes, tix: tuple[tuple[int, int], ...] = (), *,
                   wall: int | None = None, mono: int | None = None) -> None:
        """OUTX (v2) mit Zeitindex."""
        await self.send(P.encode_outx(seq, off, time.time_ns() if wall is None else wall,
                                      time.monotonic_ns() if mono is None else mono, data, tix))

    async def input(self, seq: int, off: int, data: bytes, *, out_end: int | None = None,
                    paste: bool = False, tix: tuple[tuple[int, int], ...] = (), wall: int | None = None,
                    mono: int | None = None) -> None:
        """INPUT (v2): Eingabe ans Kind."""
        await self.send(P.encode_input(seq, off, off if out_end is None else out_end,
                                       time.time_ns() if wall is None else wall,
                                       time.monotonic_ns() if mono is None else mono, data, tix,
                                       paste=paste))

    async def event(self, seq: int, kind: str, **fields: Any) -> None:
        await self.send(P.encode_json(P.EVENT, {"seq": seq, "kind": kind, **fields}))

    async def bye(self, exit_code: int | None = 0) -> None:
        await self.send(P.encode_json(P.BYE, {"exit_code": exit_code}))

    async def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
        if self._task is not None:
            self._task.cancel()


async def ctl(sock: Path, op: str, **args: Any) -> dict[str, Any]:
    reader, writer = await asyncio.open_unix_connection(str(sock))
    try:
        writer.write(json.dumps({"op": op, "args": args}).encode() + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), 30)
        return json.loads(line)
    finally:
        writer.close()


async def ctl_ok(sock: Path, op: str, **args: Any) -> Any:
    resp = await ctl(sock, op, **args)
    assert resp["ok"], resp
    return resp["result"]
