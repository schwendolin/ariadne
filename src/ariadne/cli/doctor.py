"""``ariadne doctor`` (minimal, Architektur 8.4, 8.6): prüft, was v0.1 braucht."""

from __future__ import annotations

import importlib
import os
import re
import shutil
import stat
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ariadne.cli.setup import MARK_BEGIN, SHELL_FILES
from ariadne.paths import Paths

__all__ = ["Check", "run_checks", "swap_check"]

OK, WARN, FAIL = "ok", "warn", "fail"


@dataclass(frozen=True)
class Check:
    level: str
    title: str
    detail: str = ""


def _python() -> Check:
    v = sys.version_info
    lvl = OK if v >= (3, 11) else FAIL
    return Check(lvl, f"Python {v.major}.{v.minor}.{v.micro}", "" if lvl == OK else "mindestens 3.11 nötig")


def _imports() -> list[Check]:
    out = []
    for mod in ("sqlcipher3", "pyrage", "tomlkit", "pydantic"):
        try:
            importlib.import_module(mod)
            out.append(Check(OK, f"Modul {mod}"))
        except ImportError:
            out.append(Check(FAIL, f"Modul {mod} fehlt", "pipx reinstall ariadne-recon"))
    return out


def _shell_files(paths: Paths) -> Check:
    missing = [n for n in (*SHELL_FILES, "env.sh") if not (paths.shell_dir / n).is_file()]
    if missing:
        return Check(FAIL, "Shell-Integration unvollständig",
                     "fehlt: " + ", ".join(missing) + " (ariadne setup)")
    return Check(OK, "Shell-Integration installiert")


def _rc_blocks(paths: Paths) -> list[Check]:
    out = []
    for rc in (".zshrc", ".bashrc"):
        p = paths.home / rc
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            out.append(Check(WARN, f"~/{rc} fehlt"))
            continue
        first = next((ln for ln in text.splitlines() if ln.strip()), "")
        if MARK_BEGIN not in text:
            out.append(Check(WARN, f"~/{rc}: kein Ariadne-Block", "ariadne setup"))
        elif first != MARK_BEGIN:
            out.append(Check(WARN, f"~/{rc}: Ariadne-Block nicht ganz oben"))
        else:
            out.append(Check(OK, f"~/{rc}: Ariadne-Block ganz oben"))
    return out


def _socket_dir(paths: Paths) -> Check:
    d = paths.runtime_dir
    note = "" if os.environ.get("XDG_RUNTIME_DIR") else " (ohne XDG_RUNTIME_DIR, Ausweichordner)"
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        return Check(OK, "Socket-Ordner wird beim Start angelegt" + note)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        return Check(FAIL, "Socket-Ordner ist kein echter Ordner", str(d))
    if st.st_uid != os.getuid():
        return Check(FAIL, "Socket-Ordner gehört einem anderen Benutzer", str(d))
    if st.st_mode & 0o077:
        return Check(FAIL, "Socket-Ordner ist für andere lesbar", f"chmod 700 {d}")
    return Check(OK, "Socket-Ordner sicher (0700)" + note)


def _run(argv: list[str]) -> str | None:
    env = dict(os.environ, ARIADNE_DISABLE="1")
    try:
        res = subprocess.run(argv, capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL,
                             env=env, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return res.stdout


def _grep_files(files: list[Path], pattern: str) -> bool:
    rx = re.compile(pattern, re.M | re.I)
    for f in files:
        try:
            if rx.search(f.read_text(encoding="utf-8", errors="replace")):
                return True
        except OSError:
            continue
    return False


def _bracketed_paste(paths: Paths) -> list[Check]:
    out = []
    zsh = shutil.which("zsh")
    if zsh:
        # Statisch geprüft: eine interaktive zsh ohne TTY lädt ZLE nicht und sagt nichts Verlässliches.
        ver = re.search(r"zsh (\d+)\.(\d+)", _run([zsh, "--version"]) or "")
        off = _grep_files([paths.home / ".zshrc", paths.home / ".zshenv", paths.home / ".zprofile",
                           Path("/etc/zsh/zshrc"), Path("/etc/zshrc")],
                          r"^\s*(unset\s+zle_bracketed_paste|zle_bracketed_paste=\(\s*\))")
        if off:
            out.append(Check(WARN, "zsh: Bracketed Paste abgeschaltet", "zle_bracketed_paste nicht leeren"))
        elif ver and (int(ver.group(1)), int(ver.group(2))) >= (5, 1):
            out.append(Check(OK, "zsh: Bracketed Paste aktiv (Standard ab 5.1)"))
        else:
            out.append(Check(WARN, "zsh: Bracketed Paste unbekannt"))
    bash = shutil.which("bash")
    if bash:
        bver = _run([bash, "-c", "echo ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"]) or ""
        off = _grep_files([paths.home / ".inputrc", Path("/etc/inputrc")],
                          r"^\s*set\s+enable-bracketed-paste\s+off")
        try:
            new_enough = tuple(int(x) for x in bver.strip().split(".")) >= (5, 1)
        except ValueError:
            new_enough = False
        if off:
            out.append(Check(WARN, "bash: Bracketed Paste in inputrc abgeschaltet"))
        elif new_enough:
            out.append(Check(OK, "bash: Bracketed Paste aktiv (Standard ab 5.1)"))
        else:
            out.append(Check(WARN, "bash: Bracketed Paste unbekannt", "bash vor 5.1"))
    return out


def _ptrace() -> Check:
    try:
        val = Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
    except OSError:
        return Check(WARN, "kernel.yama.ptrace_scope unbekannt", "Yama fehlt")
    if val == "0":
        return Check(WARN, "kernel.yama.ptrace_scope = 0",
                     "jeder Prozess des Benutzers darf andere auslesen; 1 empfohlen")
    return Check(OK, f"kernel.yama.ptrace_scope = {val}")


def _crypted(name: str, dm_uuid: Callable[[str], str | None],
             slaves: Callable[[str], list[str]], depth: int = 0) -> bool:
    """Liegt das Gerät auf dm-crypt? Auch über Zwischenschichten (LVM auf LUKS, Kali-Standard)."""
    if not name.startswith("dm-") or depth > 8:
        return False
    if (dm_uuid(name) or "").startswith("CRYPT-"):
        return True
    return any(_crypted(sl, dm_uuid, slaves, depth + 1) for sl in slaves(name))


def swap_check(swaps: str, dm_uuid: Callable[[str], str | None],
               slaves: Callable[[str], list[str]] | None = None,
               file_dev: Callable[[str], str | None] | None = None) -> Check:
    """Vorlauf und Puffer liegen nur im RAM (E95); unverschlüsselter Swap kann sie auf die Platte bringen.

    ``swaps`` ist der Inhalt von ``/proc/swaps``; zram und dm-crypt gelten als sicher, auch
    unter LVM (``slaves``: die Geräte unter einem dm-Gerät). Eine Swap-Datei zählt nach dem
    Gerät ihres Dateisystems (``file_dev``).
    """
    under = slaves or (lambda _n: [])
    unsafe = []
    for line in swaps.splitlines()[1:]:
        parts = line.split()
        dev = parts[0] if parts else ""
        name = os.path.basename(dev)
        if not dev or name.startswith("zram"):
            continue
        if len(parts) > 1 and parts[1] == "file" and file_dev is not None:
            name = file_dev(dev) or name
        if _crypted(name, dm_uuid, under):
            continue
        unsafe.append(dev)
    if unsafe:
        return Check(WARN, "Swap unverschlüsselt", "Vorlauf und Puffer können ausgelagert werden: "
                     + ", ".join(unsafe[:3]) + " (zram oder verschlüsselten Swap verwenden)")
    return Check(OK, "Swap: keiner, zram oder verschlüsselt")


def _swap() -> Check:
    def dm_uuid(name: str) -> str | None:
        try:
            return Path(f"/sys/block/{name}/dm/uuid").read_text().strip()
        except OSError:
            return None

    def slaves(name: str) -> list[str]:
        try:
            return sorted(os.listdir(f"/sys/block/{name}/slaves"))
        except OSError:
            return []

    def file_dev(path: str) -> str | None:
        try:
            dev = os.stat(path).st_dev
            return os.path.basename(os.readlink(f"/sys/dev/block/{os.major(dev)}:{os.minor(dev)}"))
        except OSError:
            return None

    try:
        swaps = Path("/proc/swaps").read_text()
    except OSError:
        return Check(WARN, "Swap unbekannt", "/proc/swaps nicht lesbar")
    return swap_check(swaps, dm_uuid, slaves, file_dev)


def run_checks(paths: Paths) -> list[Check]:
    return [
        _python(),
        *_imports(),
        _shell_files(paths),
        *_rc_blocks(paths),
        _socket_dir(paths),
        *_bracketed_paste(paths),
        _ptrace(),
        _swap(),
    ]
