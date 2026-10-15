"""Lokale Quellen im Daemon: Begleitdateien, Quell-IP, ausdrücklicher Import (Architektur 4.1, 4.2, 5.13).

Mark-Hook (:meth:`LocalSources.on_mark`), nur für gespeicherte, gültige Marker:

* **C-Marker**, eingegeben auf Kali: Ziele aus argv (``extract_targets``, nie
  DNS). Für jede IP-Adresse ``ip route get <ip>`` (sendet kein Paket) und ein
  ``net.route``-Event mit Quell-IP, Gerät und Gateway.
* **D-Marker** (Vordergrund geprüft) zu einem lokalen Befehl: Begleitdateien
  über ``companions_for(argv, cwd)``. Dateien im Arbeitsbereich werden sicher
  geöffnet (:mod:`ariadne.sources.safeopen`), in den Blob-Store gelegt und als
  ``file.observed`` (``origin=companion``, ``produced_by_cmd``) vermerkt.
  Dateien ausserhalb des Arbeitsbereichs oder unsichere Dateien kommen nur auf
  die Warteliste in ``state.db``, nie automatisch ins Projekt.

:meth:`LocalSources.import_file` ist ``ariadne import``: ausdrücklich, darum auch
ausserhalb des Arbeitsbereichs erlaubt, aber ebenso ohne Symlinks und nie aus
der Sperrliste.

Gelesen wird in einem Thread, Blob-Store und Journal bedient nur der Loop-Thread.
Logs enthalten keine Pfade und keine Inhalte.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ariadne.ctxrules import split_command
from ariadne.daemon.terminal import MarkContext
from ariadne.ids import cmd_id as make_cmd_id
from ariadne.ingest.segmenter import KEEPS_MARKERS
from ariadne.parsers.registry import companions_for
from ariadne.scope.targets import extract_targets
from ariadne.sources import safeopen
from ariadne.store.api import AppendItem, EventRecord

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon
    from ariadne.project.service import OpenProject

__all__ = ["LocalSources", "parse_route", "find_ip_tool", "PENDING_SQL", "list_pending"]

log = logging.getLogger("ariadne.sources")

MAX_ROUTES = 8
MAX_COMPANIONS = 16
ROUTE_TIMEOUT = 2.0
_IP_FALLBACKS = ("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip")

PENDING_SQL = """
CREATE TABLE IF NOT EXISTS pending_file (
  id          INTEGER PRIMARY KEY,
  path        TEXT NOT NULL,
  reason      TEXT NOT NULL,
  cmd_id      TEXT,
  terminal_id TEXT,
  ts_utc_ns   INTEGER NOT NULL,
  state       TEXT NOT NULL DEFAULT 'open',
  UNIQUE (path, cmd_id)
)
"""


@dataclass(frozen=True)
class _Cmd:
    cmd_id: str
    project_id: str
    argv: tuple[str, ...]
    cwd: str | None
    local: bool
    c_off: int = 0


def find_ip_tool() -> str | None:
    found = shutil.which("ip")
    if found:
        return found
    return next((p for p in _IP_FALLBACKS if os.access(p, os.X_OK)), None)


def parse_route(text: str) -> dict[str, str] | None:
    """Ausgabe von ``ip route get`` -> ``{"src_ip", "dev", "via"}`` (nur gültige Werte)."""
    tokens = text.split()
    out: dict[str, str] = {}
    for key, name in (("src", "src_ip"), ("dev", "dev"), ("via", "via")):
        if key in tokens:
            i = tokens.index(key)
            if i + 1 < len(tokens):
                out[name] = tokens[i + 1]
    for name in ("src_ip", "via"):
        if name in out:
            try:
                out[name] = str(ipaddress.ip_address(out[name]))
            except ValueError:
                del out[name]
    dev = out.get("dev")
    if dev is not None and (len(dev) > 32 or not all(c.isalnum() or c in "._-@" for c in dev)):
        del out["dev"]
    return out or None


def _ip_targets(argv: list[str]) -> list[str]:
    out: list[str] = []
    for raw in extract_targets(argv):
        try:
            ip = ipaddress.ip_address(raw.strip("[]"))
        except ValueError:
            continue  # Namen, Netze, Bereiche: kein Lookup, nie DNS
        if str(ip) not in out:
            out.append(str(ip))
    return out[:MAX_ROUTES]


def _pending_insert(project: OpenProject, rows: list[tuple[str, str, str | None, str | None]]) -> None:
    conn = project.connect_state()
    try:
        conn.execute(PENDING_SQL)
        now = time.time_ns()
        conn.executemany(
            "INSERT OR IGNORE INTO pending_file(path, reason, cmd_id, terminal_id, ts_utc_ns) "
            "VALUES (?, ?, ?, ?, ?)", [(p, r, c, t, now) for p, r, c, t in rows])
        conn.commit()
    finally:
        conn.close()


def list_pending(project: OpenProject, limit: int = 200) -> list[dict[str, Any]]:
    conn = project.connect_state()
    try:
        conn.execute(PENDING_SQL)
        rows = conn.execute("SELECT path, reason, cmd_id, terminal_id, ts_utc_ns, state FROM pending_file "
                            "WHERE state = 'open' ORDER BY ts_utc_ns DESC, id DESC LIMIT ?",
                            (int(limit),)).fetchall()
    finally:
        conn.close()
    return [{"path": r[0], "reason": r[1], "cmd_id": r[2], "terminal_id": r[3], "ts": r[4], "state": r[5]}
            for r in rows]


class LocalSources:
    def __init__(self, daemon: Daemon, *, routes: bool = True, companions: bool = True) -> None:
        self.d = daemon
        self.routes = routes
        self.companions = companions
        self._last_c: dict[str, _Cmd] = {}
        self._gap_off: dict[str, int] = {}  # Beginn der letzten Lücke, in der Marker fehlen können
        self._ip = find_ip_tool() if routes else None

    # ------------------------------------------------------------------ Commit-Hook
    def on_commit(self, records: list[EventRecord]) -> None:
        """Lücken merken: Ein D nach einer Lücke gehört nicht sicher zum C davor."""
        for r in records:
            if r.kind != "term.gap" or r.terminal_id is None:
                continue
            h = r.header
            if int(h.get("bytes_lost", 0) or 0) > 0 and h.get("reason") not in KEEPS_MARKERS:
                off = int(h.get("stream_off", 0) or 0)
                self._gap_off[r.terminal_id] = max(off, self._gap_off.get(r.terminal_id, -1))

    # ------------------------------------------------------------------ Mark-Hook
    def on_mark(self, rec: EventRecord, ctx: MarkContext | None) -> Any:
        if ctx is None or rec.terminal_id is None:
            return None
        h = rec.header
        mark = h.get("mark")
        tid = rec.terminal_id
        if mark == "C":
            text = h.get("cmd_expanded") or h.get("cmd_typed")
            argv = tuple(split_command(text)) if isinstance(text, str) else ()
            cwd = h.get("cwd") if isinstance(h.get("cwd"), str) else None
            c_off = int(h.get("stream_off", 0))
            cmd = _Cmd(make_cmd_id(tid, c_off), ctx.project_id, argv, cwd, ctx.local_before, c_off)
            self._last_c[tid] = cmd
            if cmd.local and argv and self.routes and self._ip:
                targets = _ip_targets(list(argv))
                if targets:
                    return self._routes(cmd, targets)
        elif mark == "D" and h.get("fg_shell"):
            cmd = self._last_c.pop(tid, None)
            if cmd is not None and self._gap_off.get(tid, -1) >= cmd.c_off:
                cmd = None  # REC war zwischendurch aus: der D gehört zu einem anderen Befehl
            if (cmd is not None and cmd.local and cmd.argv and self.companions
                    and cmd.project_id == ctx.project_id):
                return self._companions(cmd, tid)
        return None

    def _project(self, project_id: str) -> OpenProject | None:
        p = self.d.project
        return p if p is not None and p.info.id == project_id else None

    # ------------------------------------------------------------------ Quell-IP
    async def _route_get(self, ip: str) -> dict[str, str] | None:
        assert self._ip is not None
        try:
            proc = await asyncio.create_subprocess_exec(
                self._ip, "route", "get", ip, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                env={"LC_ALL": "C", "PATH": os.environ.get("PATH", os.defpath)})
        except OSError:
            return None
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), ROUTE_TIMEOUT)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            return None
        if proc.returncode != 0:
            return None
        return parse_route(out[:4096].decode("ascii", "replace"))

    async def _routes(self, cmd: _Cmd, targets: list[str]) -> None:
        for ip in targets:
            route = await self._route_get(ip)
            if route is None or self._project(cmd.project_id) is None:
                continue
            header = {"cmd_id": cmd.cmd_id, "target": ip, **route}
            with contextlib.suppress(Exception):
                self.d.submit(AppendItem("net.route", header, origin="daemon"))

    # ------------------------------------------------------------------ Begleitdateien
    def _blocked_extra(self) -> tuple[Path, ...]:
        pa = self.d.paths
        return (pa.config_dir, pa.data_dir, pa.state_dir, pa.runtime_dir)

    async def _companions(self, cmd: _Cmd, terminal_id: str) -> None:
        p = self._project(cmd.project_id)
        if p is None:
            return
        try:
            paths = companions_for(list(cmd.argv), cmd.cwd or "")
        except Exception as exc:
            log.warning("companions() fehlgeschlagen (%s)", type(exc).__name__)
            return
        workspace = p.info.workspace
        home = self.d.paths.home
        pending: list[tuple[str, str, str | None, str | None]] = []
        stored = 0
        for raw in paths[:MAX_COMPANIONS]:
            if not os.path.isabs(raw):
                if not cmd.cwd or not os.path.isabs(cmd.cwd):
                    continue
                raw = os.path.join(cmd.cwd, raw)
            path = os.path.normpath(raw)
            rel = safeopen.inside(path, workspace)
            if rel is None:
                pending.append((path, "outside_workspace", cmd.cmd_id, terminal_id))
                continue
            try:
                fd = await asyncio.to_thread(safeopen.read_beneath, workspace, rel, home=home,
                                             extra_blocked=self._blocked_extra())
            except safeopen.UnsafeFile as exc:
                if exc.reason != "missing":
                    pending.append((path, exc.reason, cmd.cmd_id, terminal_id))
                continue
            except OSError as exc:
                log.warning("Begleitdatei nicht lesbar (%s)", type(exc).__name__)
                continue
            if self._project(cmd.project_id) is None:
                return
            if self._store(rel, fd, origin="companion", produced_by_cmd=cmd.cmd_id,
                           context_terminal=terminal_id, rec=True):
                stored += 1
        if pending:
            try:
                await asyncio.to_thread(_pending_insert, p, pending)
            except Exception as exc:
                log.warning("Warteliste nicht geschrieben (%s)", type(exc).__name__)
        if stored or pending:
            log.info("Begleitdateien: %d gespeichert, %d auf der Warteliste", stored, len(pending))

    def _store(self, path: str, fd: safeopen.FileData, **fields: Any) -> dict[str, Any] | None:
        """Blob speichern (bis 100 MiB) und ``file.observed`` einreihen. Nur im Loop-Thread."""
        p = self.d.project
        if p is None:
            return None
        blob_id = None
        data = fd.data
        if data is not None:
            # Seit E72 ungeschwärzt (nur verschlüsselt); eigene Secrets ersetzen die Ausgänge.
            blob_id = p.blobs.put_bytes(data, kind="file").blob_id
        mime, sniffed = safeopen.sniff(data, path)
        header: dict[str, Any] = {
            "path": path, "sha256": fd.sha256, "size": fd.size, "blob_id": blob_id, "mime": mime,
            "sniff": sniffed if data is not None else "too_large", **fields,
        }
        header = {k: v for k, v in header.items() if v is not None}
        origin = "daemon" if fields.get("origin") == "companion" else "cli"
        self.d.submit(AppendItem("file.observed", header, origin=origin))
        return header

    # ------------------------------------------------------------------ ausdrücklicher Import
    async def import_file(self, path: str, host: str | None) -> dict[str, Any]:
        p = self.d.project
        if p is None:
            raise safeopen.UnsafeFile("no_project")
        if not os.path.isabs(path):
            raise safeopen.UnsafeFile("path")
        norm = os.path.normpath(path)
        rel = safeopen.inside(norm, p.info.workspace)
        home = self.d.paths.home
        if rel is not None:
            fd = await asyncio.to_thread(safeopen.read_beneath, p.info.workspace, rel, home=home,
                                         extra_blocked=self._blocked_extra())
        else:
            fd = await asyncio.to_thread(safeopen.read_absolute, norm, home=home,
                                         extra_blocked=self._blocked_extra())
        if self.d.project is not p:
            raise safeopen.UnsafeFile("project_changed")
        fields: dict[str, Any] = {"origin": "import", "rec": True}  # Daueraufnahme (E22)
        if host:
            fields["host_hint"] = host
        header = self._store(rel if rel is not None else norm, fd, **fields)
        if header is None:
            raise safeopen.UnsafeFile("no_project")
        return {"path": header["path"], "size": fd.size, "stored": fd.data is not None,
                "sha256": fd.sha256}
