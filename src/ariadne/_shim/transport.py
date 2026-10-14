"""Verbindung des Shims zum Daemon über ``term.sock`` (Architektur 3.7).

Nur Standardbibliothek. Der Transport blockiert nie: Verbindungsaufbau,
Senden und Empfangen laufen nicht blockierend in der Schleife des Shims.

* OUT und EVENT teilen eine fortlaufende ``seq`` (ab 1).
* Jeder Rahmen bleibt bis zum ACK im :class:`~ariadne._shim.ringbuf.FrameRing`.
  Nach einem Reconnect geht alles Unbestätigte ab ``resume_from_seq`` erneut
  hinaus, der Daemon verwirft Duplikate.
* Auf einer neuen Verbindung wird erst gesendet, wenn der erste ``STATE``
  angekommen ist; so kann der Shim Gepuffertes verwerfen, falls REC aus ist.
* Überlauf verwirft die ältesten Rahmen. Verlorene OUT-Bytes ergeben später
  ein ``term.gap`` mit Grund ``buffer_overflow``.
"""

from __future__ import annotations

import os
import socket
import struct
import time
from collections.abc import Callable
from typing import Any

from ariadne._shim import protocol as P
from ariadne._shim.ringbuf import Entry, FrameRing

__all__ = ["Transport", "BATCH_BYTES", "BATCH_S", "RECONNECT_S"]

BATCH_BYTES = 64 * 1024
BATCH_S = 0.05
RECONNECT_S = 1.0
WBUF_HIGH = 256 * 1024
_UCRED = struct.Struct("3i")


class Transport:
    def __init__(
        self,
        sock_path: str,
        terminal_id: str,
        hello: Callable[[], dict[str, Any]],
        ring: FrameRing,
        *,
        on_state: Callable[[dict[str, Any], bool], None] | None = None,
        on_disconnect: Callable[[], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.sock_path = sock_path
        self.terminal_id = terminal_id
        self.ring = ring
        self._hello = hello
        self.on_state = on_state
        self.on_disconnect = on_disconnect
        self._clock = clock
        self.sock: socket.socket | None = None
        self.ready = False  # erster STATE auf dieser Verbindung empfangen
        self.state: dict[str, Any] = {}
        self.next_seq = 1
        self.connections = 0
        self._last_attempt = float("-inf")
        self._decoder = P.FrameDecoder()
        self._wbuf = bytearray()
        self._queued_upto = 0
        self._rewind = False
        self._out = bytearray()
        self._out_off = 0
        self._out_wall = 0
        self._out_mono = 0
        self._out_t0 = 0.0
        self.gap_start: int | None = None
        self.gap_bytes = 0

    # ----------------------------------------------------------- Verbindung

    @property
    def connected(self) -> bool:
        return self.sock is not None

    def fileno(self) -> int:
        return self.sock.fileno() if self.sock is not None else -1

    def try_connect(self, now: float) -> bool:
        """Ein Verbindungsversuch, höchstens einmal pro Sekunde."""
        if self.sock is not None or now < self._last_attempt + RECONNECT_S:
            return self.sock is not None
        self._last_attempt = now
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC)
        try:
            s.connect(self.sock_path)
            raw = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _UCRED.size)
            _pid, uid, _gid = _UCRED.unpack(raw)
            if uid != os.getuid():
                raise PermissionError("fremder Daemon")
        except (OSError, ValueError, struct.error):
            s.close()
            return False
        self.sock = s
        self.connections += 1
        self.ready = False
        self._decoder = P.FrameDecoder()
        first = self.ring.first_seq
        hello = dict(self._hello())
        hello["resume_from_seq"] = first
        if self.gap_start is not None:
            # Rahmen sind verdrängt: Der Daemon sieht den Sprung im Offset vor unserem
            # term.gap (das erst bei halb leerem Ring kommt) und braucht den Grund.
            hello["gap_hint"] = "buffer_overflow"
        self._wbuf = bytearray(P.encode_json(P.HELLO, hello))
        self._queued_upto = (first - 1) if first is not None else self.next_seq - 1
        self._rewind = False
        return True

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.close()
        finally:
            self.sock = None
            self.ready = False
            self._wbuf = bytearray()
            self._decoder = P.FrameDecoder()
            self._last_attempt = self._clock()
            if self.on_disconnect is not None:
                self.on_disconnect()

    def wants_write(self) -> bool:
        if self.sock is None:
            return False
        if self._wbuf:
            return True
        last = self.ring.last_seq
        return self.ready and last is not None and last > self._queued_upto

    def rewind(self) -> None:
        """Alles Unbestätigte noch einmal senden (z. B. nach ``waiting`` -> ``on``)."""
        self._rewind = True

    # --------------------------------------------------------------- Inhalt

    def add_out(self, data: bytes, stream_off: int, wall_ns: int, mono_ns: int, now: float) -> None:
        if not data:
            return
        if self._out and self._out_off + len(self._out) != stream_off:
            self.flush_out()
        if not self._out:
            self._out_off, self._out_wall, self._out_mono, self._out_t0 = stream_off, wall_ns, mono_ns, now
        self._out += data
        if len(self._out) >= BATCH_BYTES:
            self.flush_out()

    def flush_out(self) -> None:
        while self._out:
            chunk = bytes(self._out[:BATCH_BYTES])
            del self._out[:BATCH_BYTES]
            seq = self._take_seq()
            frame = P.encode_out(seq, self._out_off, self._out_wall, self._out_mono, chunk)
            self._append(seq, frame, len(chunk), self._out_off)
            self._out_off += len(chunk)

    def add_event(self, kind: str, fields: dict[str, Any]) -> int:
        self.flush_out()
        seq = self._take_seq()
        frame = P.encode_json(P.EVENT, {"seq": seq, "kind": kind, **fields})
        self._append(seq, frame)
        return seq

    def drop_unacked(self) -> int | None:
        """Verwirft alles Unbestätigte. Gibt den ersten verworfenen Stream-Offset zurück."""
        first: int | None = None
        if self._out:
            first = self._out_off
            self._out = bytearray()
        for e in self.ring.clear():
            if e.stream_off is not None and (first is None or e.stream_off < first):
                first = e.stream_off
        if self.sock is not None:
            self._queued_upto = self.next_seq - 1
        return first

    def pending_out(self) -> int:
        return len(self._out)

    def _take_seq(self) -> int:
        seq = self.next_seq
        self.next_seq += 1
        return seq

    def _append(self, seq: int, frame: bytes, data_len: int = 0, stream_off: int | None = None) -> None:
        for e in self.ring.append(seq, frame, data_len, stream_off):
            self._lost(e)

    def _lost(self, e: Entry) -> None:
        if self.sock is not None and e.seq <= self._queued_upto:
            return  # schon unterwegs
        if e.stream_off is None:
            return
        if self.gap_start is None or e.stream_off < self.gap_start:
            self.gap_start = e.stream_off
        self.gap_bytes += e.data_len

    # ----------------------------------------------------------- Ein/Ausgabe

    def deadline(self) -> float | None:
        d: float | None = None
        if self._out:
            d = self._out_t0 + BATCH_S
        if self.sock is None:
            r = self._last_attempt + RECONNECT_S
            d = r if d is None else min(d, r)
        return d

    def tick(self, now: float) -> None:
        if self._out and now >= self._out_t0 + BATCH_S:
            self.flush_out()
        if self.sock is None:
            self.try_connect(now)
        if self.gap_start is not None and self.ring.used * 2 <= self.ring.capacity:
            start, lost = self.gap_start, self.gap_bytes
            self.gap_start, self.gap_bytes = None, 0
            self.add_event("term.gap", {"terminal_id": self.terminal_id, "stream_off": start,
                                        "reason": "buffer_overflow", "bytes_lost": lost})

    def on_readable(self) -> None:
        if self.sock is None:
            return
        try:
            data = self.sock.recv(65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            self.close()
            return
        if not data:
            self.close()
            return
        try:
            frames = self._decoder.feed(data)
        except P.ProtocolError:
            self.close()
            return
        for fr in frames:
            if fr.type == P.ACK:
                try:
                    seq = P.decode_json(fr.payload).get("seq")
                except P.ProtocolError:
                    continue
                if isinstance(seq, int) and not isinstance(seq, bool):
                    self.ring.release_upto(seq)
            elif fr.type == P.STATE:
                try:
                    st = P.decode_json(fr.payload)
                except P.ProtocolError:
                    continue
                first = not self.ready
                self.state = st
                self.ready = True
                if self.on_state is not None:
                    self.on_state(st, first)
                if self.sock is None:
                    return

    def on_writable(self) -> None:
        self._pump()

    def _pump(self) -> None:
        if self.sock is None:
            return
        if self._rewind and not self._wbuf:
            self._rewind = False
            first = self.ring.first_seq
            self._queued_upto = (first - 1) if first is not None else self.next_seq - 1
        if self.ready:
            while len(self._wbuf) < WBUF_HIGH:
                seq = self._queued_upto + 1
                frame = self.ring.get(seq)
                if frame is None:
                    first = self.ring.first_seq
                    if first is not None and first > seq:
                        self._queued_upto = first - 1  # verdrängt, nie gesendet
                        continue
                    break
                self._wbuf += frame
                self._queued_upto = seq
        while self._wbuf:
            try:
                n = self.sock.send(self._wbuf)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self.close()
                return
            del self._wbuf[:n]

    # ------------------------------------------------------------- Abschied

    def bye(self, exit_code: int | None, timeout: float = 0.5) -> None:
        """Sendet Rest und ``BYE`` mit kurzer Frist. Blockiert höchstens ``timeout``."""
        import selectors

        self.flush_out()
        if self.sock is None:
            return
        end = self._clock() + timeout
        sel = selectors.DefaultSelector()
        try:
            sel.register(self.sock, selectors.EVENT_READ | selectors.EVENT_WRITE)
            bye_sent = False
            while self.sock is not None and self._clock() < end:
                self._pump()
                if self.sock is None:
                    break
                if not self.wants_write():
                    if bye_sent:
                        break
                    self._wbuf += P.encode_json(P.BYE, {"exit_code": exit_code})
                    bye_sent = True
                    continue
                for _key, mask in sel.select(max(0.0, end - self._clock())):
                    if mask & selectors.EVENT_READ:
                        self.on_readable()
                    if self.sock is None:
                        break
        except OSError:
            pass
        finally:
            sel.close()
            if self.sock is not None:
                cb, self.on_disconnect = self.on_disconnect, None
                self.close()
                self.on_disconnect = cb
