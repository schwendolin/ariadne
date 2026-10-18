"""«In die Kali kopieren» (E111, ``docs/web-api.md`` 18.7): ein Secret-Wert in die Zwischenablage
der grafischen Sitzung der Kali, ohne dass er je an den Browser geht.

* Werkzeug: bei Wayland ``wl-copy``, bei X11 ``xclip -selection clipboard`` oder
  ``xsel --clipboard --input`` (in dieser Reihenfolge, was vorhanden ist). Fehlt ein passendes
  Werkzeug: :class:`ClipboardError` ``clipboard_tool``.
* Sitzung: ``DISPLAY``, ``WAYLAND_DISPLAY``, ``XAUTHORITY``, ``XDG_RUNTIME_DIR`` aus der eigenen
  Umgebung oder aus ``/proc/<pid>/environ`` eines Prozesses **derselben UID**, der zu einer
  grafischen Sitzung gehört (``XDG_SESSION_TYPE`` ist ``x11`` oder ``wayland``). Prozesse anderer
  Benutzer liest der Daemon nie. Ohne Treffer: ``clipboard_session``.
* Der Wert geht nur über stdin an das Werkzeug, nie in argv, nie ins Log; das Werkzeug bekommt nur
  eine kleine Umgebung (``PATH``, ``HOME``, ``LANG`` und die Sitzungsvariablen).
* Nach 30 s liest der Daemon die Zwischenablage zurück und leert sie, wenn noch derselbe Inhalt
  darin ist (Vergleich über SHA-256; der Wert selbst wird nicht behalten). Lässt sie sich nicht
  zurücklesen, wird sie trotzdem geleert (ein Secret liegt lieber nicht herum). Beim Ende des
  Daemons werden offene Fristen sofort abgearbeitet.

Besitzer: Teil «backend-ui» des Baus v0.1-Oberfläche. Die ctl-Operation ``clip.copy`` steht in
``daemon/core.py``; diese Datei kennt keine Projekte.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = ["Clipboard", "ClipboardError", "Tool", "CLEAR_AFTER_S", "find_session", "TOOL_ORDER"]

log = logging.getLogger("ariadne.daemon")

CLEAR_AFTER_S = 30.0
RUN_TIMEOUT_S = 5.0
ENVIRON_MAX = 128 * 1024
VALUE_MAX = 64 * 1024
_DISPLAY_RE = re.compile(r"^[A-Za-z0-9._/-]{0,200}:[0-9]{1,5}(\.[0-9]{1,3})?$")
_WAYLAND_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]{0,255}$")
_SESSION_KEYS = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR")
_DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"
TOOL_ORDER = ("wl-copy", "xclip", "xsel")


class ClipboardError(Exception):
    """``code``: ``clipboard_tool`` oder ``clipboard_session`` (Web-API 503)."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Tool:
    name: str  # 'wl-copy', 'xclip', 'xsel' (Antwort der API)
    copy: tuple[str, ...]  # liest den Wert von stdin
    paste: tuple[str, ...] | None  # gibt den Inhalt auf stdout aus
    clear: tuple[str, ...]  # leert (bei xclip: leeres stdin)


def _tools(which: Any) -> dict[str, Tool]:
    out: dict[str, Tool] = {}
    wl = which("wl-copy")
    if wl:
        paste = which("wl-paste")
        out["wl-copy"] = Tool("wl-copy", (wl,), (paste, "--no-newline") if paste else None, (wl, "--clear"))
    xc = which("xclip")
    if xc:
        out["xclip"] = Tool(
            "xclip",
            (xc, "-selection", "clipboard", "-in"),
            (xc, "-selection", "clipboard", "-out"),
            (xc, "-selection", "clipboard", "-in"),
        )
    xs = which("xsel")
    if xs:
        out["xsel"] = Tool(
            "xsel",
            (xs, "--clipboard", "--input"),
            (xs, "--clipboard", "--output"),
            (xs, "--clipboard", "--clear"),
        )
    return out


def _valid_session(env: Mapping[str, str]) -> dict[str, str] | None:
    out: dict[str, str] = {}
    disp = env.get("DISPLAY")
    if isinstance(disp, str) and _DISPLAY_RE.match(disp):
        out["DISPLAY"] = disp
    way = env.get("WAYLAND_DISPLAY")
    if isinstance(way, str) and _WAYLAND_RE.match(way):
        out["WAYLAND_DISPLAY"] = way
    if not out:
        return None
    for key in ("XAUTHORITY", "XDG_RUNTIME_DIR"):
        v = env.get(key)
        if isinstance(v, str) and _PATH_RE.match(v) and ".." not in v.split("/"):
            out[key] = v
    return out


def _read_environ(path: Path) -> dict[str, str] | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        raw = os.read(fd, ENVIRON_MAX + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(raw) > ENVIRON_MAX:
        raw = raw[:ENVIRON_MAX]
    out: dict[str, str] = {}
    for item in raw.split(b"\0"):
        key, sep, val = item.partition(b"=")
        if not sep:
            continue
        k = key.decode("ascii", "replace")
        if k in (*_SESSION_KEYS, "XDG_SESSION_TYPE"):
            out[k] = val.decode("utf-8", "replace")
    return out


def find_session(
    env: Mapping[str, str] | None = None, *, proc_root: Path = Path("/proc"), uid: int | None = None
) -> dict[str, str] | None:
    """Umgebung der grafischen Sitzung oder ``None``.

    Zuerst die eigene Umgebung; sonst der Prozess mit der kleinsten PID, der derselben UID gehört
    und eine grafische Sitzung hat (``XDG_SESSION_TYPE`` ``x11``/``wayland`` und ``DISPLAY`` oder
    ``WAYLAND_DISPLAY``). Fehlt ``XDG_RUNTIME_DIR``, gilt der eigene Wert."""
    own_env = dict(os.environ if env is None else env)
    me = os.getuid() if uid is None else uid
    found = _valid_session(own_env)
    if found is None:
        try:
            entries = sorted(
                (e for e in os.scandir(proc_root) if e.name.isdigit()), key=lambda e: int(e.name)
            )
        except OSError:
            entries = []
        for e in entries:
            try:
                st = os.stat(e.path, follow_symlinks=False)
            except OSError:
                continue
            if st.st_uid != me:  # nie Prozesse anderer Benutzer
                continue
            penv = _read_environ(Path(e.path) / "environ")
            if not penv or penv.get("XDG_SESSION_TYPE") not in ("x11", "wayland"):
                continue
            found = _valid_session(penv)
            if found is not None:
                break
    if found is None:
        return None
    if "XDG_RUNTIME_DIR" not in found:
        own = own_env.get("XDG_RUNTIME_DIR")
        if isinstance(own, str) and _PATH_RE.match(own):
            found["XDG_RUNTIME_DIR"] = own
    return found


def _digest(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


@dataclass
class Clipboard:
    """Zwischenablage der Kali. ``path`` ist der Suchpfad der Werkzeuge (Standard: ``PATH`` des
    Daemons plus die üblichen Systemordner), ``env`` und ``proc_root`` die Quellen der Sitzung;
    alles austauschbar für Tests."""

    path: str | None = None
    env: Mapping[str, str] | None = None
    proc_root: Path = Path("/proc")
    clear_after_s: float = CLEAR_AFTER_S
    _pending: dict[str, asyncio.TimerHandle] = field(default_factory=dict)
    _jobs: dict[str, tuple[Tool, dict[str, str], bytes]] = field(default_factory=dict)
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    def _search(self) -> str:
        if self.path is not None:
            return self.path
        base = os.environ.get("PATH", "")
        return f"{base}:{_DEFAULT_PATH}" if base else _DEFAULT_PATH

    def _which(self, name: str) -> str | None:
        return shutil.which(name, path=self._search())

    def choose(self) -> tuple[Tool, dict[str, str]]:
        """Werkzeug und Sitzung; sonst :class:`ClipboardError`."""
        tools = _tools(self._which)
        if not tools:
            raise ClipboardError("clipboard_tool")
        session = find_session(self.env, proc_root=self.proc_root)
        if session is None:
            raise ClipboardError("clipboard_session")
        order = []
        if "WAYLAND_DISPLAY" in session:
            order.append("wl-copy")
        if "DISPLAY" in session:
            order += ["xclip", "xsel"]
        for name in order:
            if name in tools:
                return tools[name], session
        raise ClipboardError("clipboard_tool")

    def _env(self, session: Mapping[str, str]) -> dict[str, str]:
        env = {"PATH": self._search(), "LANG": "C.UTF-8"}
        home = os.environ.get("HOME")
        if home:
            env["HOME"] = home
        env.update(session)
        return env

    async def _run(
        self, argv: tuple[str, ...], env: dict[str, str], data: bytes | None, *, want_out: bool = False
    ) -> bytes | None:
        """Startet das Werkzeug ohne Shell; stdin bekommt ``data``. Ausgaben nur, wenn gewünscht
        (die Kopierwerkzeuge laufen danach im Hintergrund weiter und dürfen keine Pipe halten)."""
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE if want_out else asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        try:
            out, _err = await asyncio.wait_for(proc.communicate(data), RUN_TIMEOUT_S)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            await proc.wait()
            raise OSError("Werkzeug antwortet nicht") from None
        if proc.returncode != 0:
            raise OSError("Werkzeug fehlgeschlagen")
        return out if want_out else None

    async def copy(self, value: str, key: str = "clip") -> str:
        """Kopiert ``value`` und plant das Leeren. Gibt den Namen des Werkzeugs zurück."""
        data = value.encode("utf-8")
        if not data or len(data) > VALUE_MAX:
            raise ValueError("Wert leer oder zu gross")
        tool, session = self.choose()
        env = self._env(session)
        await self._run(tool.copy, env, data)
        self._schedule(key, tool, env, _digest(data))
        log.info("Wert in die Zwischenablage der Kali kopiert (%s)", tool.name)
        return tool.name

    def _schedule(self, key: str, tool: Tool, env: dict[str, str], digest: bytes) -> None:
        old = self._pending.pop(key, None)
        if old is not None:
            old.cancel()
        self._jobs[key] = (tool, env, digest)
        loop = asyncio.get_running_loop()
        self._pending[key] = loop.call_later(self.clear_after_s, self._fire, key)

    def _fire(self, key: str) -> None:
        self._pending.pop(key, None)
        job = self._jobs.pop(key, None)
        if job is None:
            return
        task = asyncio.ensure_future(self._clear(*job))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _clear(self, tool: Tool, env: dict[str, str], digest: bytes) -> bool:
        """Leert, wenn noch derselbe Inhalt darin ist (oder er sich nicht lesen lässt)."""
        same = True
        if tool.paste is not None:
            try:
                cur = await self._run(tool.paste, env, None, want_out=True)
                same = cur is not None and _digest(cur) == digest
            except OSError:
                same = True
        if not same:
            return False
        try:
            await self._run(tool.clear, env, b"" if tool.name == "xclip" else None)
        except OSError:
            log.warning("Zwischenablage der Kali nicht geleert (%s)", tool.name)
            return False
        log.info("Zwischenablage der Kali geleert (%s)", tool.name)
        return True

    @property
    def pending(self) -> int:
        return len(self._pending)

    async def close(self) -> None:
        """Offene Fristen sofort abarbeiten (Ende des Daemons)."""
        for key in list(self._pending):
            handle = self._pending.pop(key)
            handle.cancel()
            job = self._jobs.pop(key, None)
            if job is not None:
                with contextlib.suppress(Exception):
                    await self._clear(*job)
        for task in list(self._tasks):
            with contextlib.suppress(Exception):
                await task
