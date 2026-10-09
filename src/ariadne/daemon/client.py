"""Synchroner Client für ``ctl.sock`` (CLI). Prüft die UID des Daemons per ``SO_PEERCRED``."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from typing import Any

from ariadne.daemon.hardening import peer_cred

__all__ = ["CtlClient", "CtlError", "DaemonUnavailable"]


class DaemonUnavailable(ConnectionError):
    pass


class CtlError(RuntimeError):
    def __init__(self, code: str, message: str, extra: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.extra = extra or {}


class CtlClient:
    def __init__(self, path: Path, timeout: float = 120.0) -> None:
        self.path = path
        self.timeout = timeout

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        s.settimeout(self.timeout)
        try:
            s.connect(str(self.path))
        except OSError as exc:
            s.close()
            raise DaemonUnavailable("Daemon nicht erreichbar") from exc
        try:
            _pid, uid, _gid = peer_cred(s)
        except OSError as exc:
            s.close()
            raise DaemonUnavailable("Peer-Prüfung fehlgeschlagen") from exc
        if uid != os.getuid():
            s.close()
            raise DaemonUnavailable("ctl.sock gehört einem anderen Benutzer")
        return s

    def ping(self) -> bool:
        try:
            self.call("ping", timeout=2.0)
            return True
        except (DaemonUnavailable, CtlError, OSError):
            return False

    def call(self, op: str, timeout: float | None = None, **args: Any) -> Any:
        s = self._connect()
        if timeout is not None:
            s.settimeout(timeout)
        try:
            s.sendall(json.dumps({"op": op, "args": args}).encode() + b"\n")
            buf = bytearray()
            while not buf.endswith(b"\n"):
                chunk = s.recv(1 << 16)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > (8 << 20):
                    raise CtlError("protocol", "Antwort zu gross")
        except OSError as exc:
            raise DaemonUnavailable("Verbindung zum Daemon abgebrochen") from exc
        finally:
            s.close()
        try:
            resp = json.loads(bytes(buf))
        except ValueError as exc:
            raise CtlError("protocol", "ungültige Antwort des Daemons") from exc
        if not resp.get("ok"):
            err = resp.get("error") or {}
            extra = {k: v for k, v in err.items() if k not in ("code", "message")}
            raise CtlError(str(err.get("code", "error")), str(err.get("message", "Fehler")), extra)
        return resp.get("result")
