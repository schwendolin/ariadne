"""Start des Shims: Prüfungen, PTY, Kindprozess (Architektur 3.1, 3.2).

Nur Standardbibliothek und bewusst schlank: Hier wird so wenig wie möglich
importiert, damit die Shell früh startet. Die schweren Module (Scanner,
Transport, Kontext-Stapel) lädt :func:`run` erst nach dem ``fork``, während
die Shell ihre RC-Dateien liest.

* Jeder Fehler vor dem ``fork`` endet in der nackten Shell
  (:func:`fallback_exec`, ``ARIADNE_SHIM_FAILED=<grund>``).
* Scheitert danach das Laden des Relays, übernimmt :func:`plain_relay`:
  Ein- und Ausgabe ohne Aufnahme, die Shell läuft weiter.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import select
import struct
import termios
import time

from ariadne._shim import procutil
from ariadne.ids import new_id, new_nonce

TYPE_CHECKING = False  # typing nicht laden: jede Millisekunde vor dem fork zählt
if TYPE_CHECKING:
    from typing import NoReturn

__all__ = ["Spawned", "run", "fallback_exec", "precheck", "spawn", "plain_relay", "make_raw"]


class Spawned:
    """Ergebnis von :func:`spawn` (bewusst ohne dataclasses, das kostet Startzeit)."""

    __slots__ = ("argv", "env", "master", "child", "tty_name", "attrs", "rows", "cols", "terminal_id",
                 "nonce")

    def __init__(self, argv: list[str], env: dict[str, str], master: int, child: int, tty_name: str,
                 attrs: list, rows: int, cols: int, terminal_id: str, nonce: str) -> None:
        self.argv = argv
        self.env = env
        self.master = master
        self.child = child
        self.tty_name = tty_name
        self.attrs = attrs
        self.rows = rows
        self.cols = cols
        self.terminal_id = terminal_id
        self.nonce = nonce


def fallback_exec(argv: list[str], reason: str) -> NoReturn:
    """Startet die Shell ohne Shim. Kehrt nie zurück."""
    env = dict(os.environ)
    env["ARIADNE_SHIM_FAILED"] = reason
    shell = env.get("SHELL") or ""
    for cand in (argv, [shell, "-i"], ["/bin/sh", "-i"]):
        if cand and cand[0]:
            with contextlib.suppress(OSError):
                os.execvpe(cand[0], cand, env)  # noqa: S606 - Shell ohne Shim, kein sh -c
    os._exit(127)


def winsize(fd: int) -> tuple[int, int]:
    try:
        rows, cols, _x, _y = struct.unpack("HHHH", fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8))
    except OSError:
        return 24, 80
    return (rows or 24), (cols or 80)


def set_winsize(fd: int, rows: int, cols: int) -> None:
    with contextlib.suppress(OSError):
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


def make_raw(attrs: list) -> list:
    new = [list(a) if isinstance(a, list) else a for a in attrs]
    new[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP
                | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
    new[1] &= ~termios.OPOST
    new[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
    new[2] &= ~(termios.CSIZE | termios.PARENB)
    new[2] |= termios.CS8
    new[6][termios.VMIN] = 1
    new[6][termios.VTIME] = 0
    return new


def exit_code(status: int) -> int:
    code = os.waitstatus_to_exitcode(status)
    return 128 - code if code < 0 else code


def precheck(argv: list[str]) -> str | None:
    """Gründe, gar nicht erst zu wrappen (vor jedem Seiteneffekt)."""
    if not argv:
        return "args"
    if not (os.isatty(0) and os.isatty(1)):
        return "notty"
    # Nur «nested», wenn ein Shim schon genau dieses Terminal aufnimmt. Ein neues
    # Terminal-Fenster aus einer aufgezeichneten Shell hat ein eigenes PTY.
    try:
        rdev = os.fstat(0).st_rdev
    except OSError:
        return "notty"
    if procutil.shim_owns_tty(procutil.SHIM_NAME, rdev):
        return "nested"
    return None


def _child(argv: list[str], env: dict[str, str], slave: int) -> NoReturn:
    try:
        import signal

        os.login_tty(slave)
        with contextlib.suppress(OSError, ValueError):
            signal.set_wakeup_fd(-1)
        for sig in signal.valid_signals():
            if sig not in (signal.SIGKILL, signal.SIGSTOP):
                with contextlib.suppress(OSError, ValueError):
                    signal.signal(sig, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, set())
        os.execvpe(argv[0], argv, env)  # noqa: S606 - die Shell selbst
    finally:
        os._exit(127)


def spawn(argv: list[str], env: dict[str, str] | None = None) -> Spawned:
    """PTY anlegen und die Shell darin starten. Wirft bei Fehlern vor dem fork."""
    env = dict(os.environ if env is None else env)
    procutil.set_process_name()
    attrs = termios.tcgetattr(0)
    rows, cols = winsize(0)
    master, slave = os.openpty()
    try:
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        set_winsize(slave, rows, cols)
        tty_name = os.ttyname(slave)
    except OSError:
        os.close(master)
        os.close(slave)
        raise
    terminal_id, nonce = new_id(), new_nonce()
    child_env = dict(env)
    child_env.pop("ARIADNE_SHIM_FAILED", None)
    child_env.update({
        "ARIADNE_SHIM_TTY": tty_name,
        "ARIADNE_NONCE": nonce,
        "ARIADNE_TERMINAL_ID": terminal_id,
        "ARIADNE_SHIM_PID": str(os.getpid()),
    })
    pid = os.fork()
    if pid == 0:
        os.close(master)
        _child(argv, child_env, slave)
    os.close(slave)
    procutil.harden_parent()
    return Spawned(argv, env, master, pid, tty_name, attrs, rows, cols, terminal_id, nonce)


def plain_relay(sp: Spawned) -> int:
    """Notfall-Relay ohne Scanner, Hotkeys und Aufnahme. Gibt den Exit-Code zurück."""
    status: int | None = None
    try:
        with contextlib.suppress(termios.error, OSError):
            termios.tcsetattr(0, termios.TCSANOW, make_raw(sp.attrs))
        with contextlib.suppress(OSError):
            _write_all(1, b"\x1b]2;[ariadne inaktiv] Shim-Fehler, keine Aufnahme\x07")
        last = time.monotonic()
        while True:
            try:
                r, _, _ = select.select([0, sp.master], [], [], 0.2)
            except InterruptedError:
                continue
            if sp.master in r:
                try:
                    data = os.read(sp.master, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                last = time.monotonic()
                _write_all(1, data)
            if 0 in r:
                try:
                    data = os.read(0, 65536)
                except OSError:
                    data = b""
                if not data:
                    break
                _write_all(sp.master, data)
            if status is None:
                pid, st = os.waitpid(sp.child, os.WNOHANG)
                if pid == sp.child:
                    status = st
            if status is not None and time.monotonic() - last > 0.1:
                break
    except OSError:
        pass
    finally:
        with contextlib.suppress(termios.error, OSError):
            termios.tcsetattr(0, termios.TCSADRAIN, sp.attrs)
        with contextlib.suppress(OSError):
            os.close(sp.master)
    if status is None:
        with contextlib.suppress(OSError):
            pid, status = os.waitpid(sp.child, 0)
    return exit_code(status) if status is not None else 129


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except (BlockingIOError, InterruptedError):
            select.select([], [fd], [], 1.0)
            continue
        view = view[n:]


def run(argv: list[str]) -> int:
    """Startet den Shim. Vor dem fork endet jeder Fehler in der nackten Shell."""
    argv = list(argv) or [os.environ.get("SHELL") or "/bin/sh", "-i"]
    try:
        reason = precheck(argv)
        if reason is not None:
            fallback_exec(argv, reason)
        sp = spawn(argv)
    except BaseException:
        fallback_exec(argv, "start")
    try:
        from ariadne._shim.relay import Shim

        shim = Shim(sp)
        shim.setup()
    except BaseException:
        return plain_relay(sp)
    return shim.serve()
