"""Fake-Daemon für Shim-Tests: nimmt Shim-Verbindungen auf ``term.sock`` an.

Läuft in einem Thread, zeichnet alle Rahmen auf, schickt nach ``HELLO`` einen
``STATE`` und bestätigt OUT, OUTX, INPUT und EVENT per ``ACK`` (abschaltbar).
``req.pause`` schaltet wie der echte Daemon um (``paused`` mit ``pause_until_ns``).
"""

from __future__ import annotations

import os
import selectors
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ariadne._shim import protocol as P


@dataclass
class Rec:
    conn: int
    type: int
    obj: Any  # dict für JSON, (seq, off, wall, mono, data, tix) für OUT/OUTX, InputFrame für INPUT
    t: float = field(default_factory=time.monotonic)


class FakeDaemon:
    def __init__(self, sock_path: Path, *, rec: str = "on", project: str | None = "lame",
                 ack: bool = True, hosts: list[str] | None = None) -> None:
        self.sock_path = Path(sock_path)
        self.state: dict[str, Any] = {
            "rec": rec, "project": project, "project_id": "p1", "profile": "lab",
            "bound_project_id": None, "stack": [], "suggestion": None, "pause_until_ns": None,
            "preroll_minutes": 15,
            "hosts": hosts if hosts is not None else ["web01", "web02", "db01"], "title_extra": None,
        }
        self.ack = ack
        self.records: list[Rec] = []
        self._lock = threading.Lock()
        self._conns: dict[int, socket.socket] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._srv: socket.socket | None = None

    # ------------------------------------------------------------ Lebenszyklus

    def start(self) -> FakeDaemon:
        self.sock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.sock_path.exists():
            self.sock_path.unlink()
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.sock_path))
        srv.listen(8)
        srv.setblocking(False)
        self._srv = srv
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(2)
        for c in list(self._conns.values()):
            c.close()
        if self._srv is not None:
            self._srv.close()
        if self.sock_path.exists():
            self.sock_path.unlink()

    def __enter__(self) -> FakeDaemon:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ---------------------------------------------------------------- Abfragen

    def frames(self, ftype: int | None = None) -> list[Rec]:
        with self._lock:
            return [r for r in self.records if ftype is None or r.type == ftype]

    def events(self, kind: str | None = None) -> list[dict]:
        return [r.obj for r in self.frames(P.EVENT) if kind is None or r.obj.get("kind") == kind]

    def hellos(self) -> list[dict]:
        return [r.obj for r in self.frames(P.HELLO)]

    def out_bytes(self) -> bytes:
        """Aufgezeichneter Strom, nach Offset sortiert, Duplikate entfernt."""
        chunks: dict[int, bytes] = {}
        for r in self.frames(P.OUT) + self.frames(P.OUTX):
            off, data = r.obj[1], r.obj[4]
            chunks.setdefault(off, data)
        return b"".join(chunks[k] for k in sorted(chunks))

    def outs(self) -> list[Rec]:
        return self.frames(P.OUT) + self.frames(P.OUTX)

    def inputs(self) -> list[P.InputFrame]:
        return [r.obj for r in self.frames(P.INPUT)]

    def input_bytes(self) -> bytes:
        return b"".join(f.data for f in self.inputs())

    def marks(self, mark: str | None = None) -> list[dict]:
        return [e for e in self.events("term.mark") if mark is None or e.get("mark") == mark]

    def wait_for(self, pred: Callable[[], Any], timeout: float = 5.0) -> Any:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            v = pred()
            if v:
                return v
            time.sleep(0.02)
        return pred()

    def send_state(self, **changes: Any) -> None:
        self.state.update(changes)
        data = P.encode_json(P.STATE, self.state)
        for c in list(self._conns.values()):
            try:
                c.sendall(data)
            except OSError:
                pass

    # ------------------------------------------------------------------ intern

    def _run(self) -> None:
        sel = selectors.DefaultSelector()
        assert self._srv is not None
        sel.register(self._srv, selectors.EVENT_READ, None)
        decoders: dict[int, P.FrameDecoder] = {}
        cid = 0
        while not self._stop.is_set():
            for key, _mask in sel.select(0.05):
                if key.data is None:
                    try:
                        conn, _ = self._srv.accept()
                    except OSError:
                        continue
                    cid += 1
                    conn.setblocking(True)
                    self._conns[cid] = conn
                    decoders[cid] = P.FrameDecoder()
                    sel.register(conn, selectors.EVENT_READ, cid)
                    continue
                c = key.data
                conn = self._conns.get(c)
                if conn is None:
                    continue
                try:
                    data = conn.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(conn)
                    conn.close()
                    self._conns.pop(c, None)
                    continue
                for fr in decoders[c].feed(data):
                    self._handle(c, conn, fr)
        sel.close()

    def _handle(self, c: int, conn: socket.socket, fr: P.Frame) -> None:
        if fr.type == P.OUT:
            obj: Any = (*P.decode_out(fr.payload), ())
            seq = obj[0]
        elif fr.type == P.OUTX:
            ox = P.decode_outx(fr.payload)
            obj = (ox.seq, ox.stream_off, ox.t_wall_ns, ox.t_mono_ns, ox.data, ox.tix)
            seq = ox.seq
        elif fr.type == P.INPUT:
            obj = P.decode_input(fr.payload)
            seq = obj.seq
        else:
            obj = P.decode_json(fr.payload)
            seq = obj.get("seq")
        with self._lock:
            self.records.append(Rec(c, fr.type, obj))
        try:
            if fr.type == P.HELLO:
                conn.sendall(P.encode_json(P.STATE, self.state))
            elif fr.type in (P.OUT, P.OUTX, P.INPUT, P.EVENT) and self.ack and isinstance(seq, int):
                conn.sendall(P.encode_json(P.ACK, {"seq": seq}))
            if fr.type == P.EVENT and obj.get("kind") == "req.rec":
                on = obj.get("on")
                if on is None:
                    on = self.state["rec"] != "on"
                new = "on" if on else "off"
                self.state["rec"] = new
                conn.sendall(P.encode_json(P.STATE, self.state))
            if fr.type == P.EVENT and obj.get("kind") == "req.pause":
                minutes = obj.get("minutes")
                paused = self.state["rec"] == "paused"
                if minutes is None:
                    minutes = 0 if paused else 10
                if minutes:
                    self.state["rec"] = "paused"
                    self.state["pause_until_ns"] = time.time_ns() + minutes * 60_000_000_000
                else:
                    self.state["rec"] = "on"
                    self.state["pause_until_ns"] = None
                conn.sendall(P.encode_json(P.STATE, self.state))
        except OSError:
            pass


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
