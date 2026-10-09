"""``ariadne setup``: einziger Installer (Architektur 3.1, 8.6).

* Shell-Dateien aus dem Paket (``ariadne/shell``) nach ``paths.shell_dir``.
* ``env.sh`` mit Interpreter, Paketordner und Hotkey für den Launcher.
* RC-Block ganz oben in ``~/.zshrc`` und ``~/.bashrc`` (idempotent, entfernbar).
* systemd-User-Unit ``ariadned.service``.

``--remove`` baut alles wieder ab, Tresor und Projekte bleiben unangetastet.
"""

from __future__ import annotations

import contextlib
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path

import ariadne
from ariadne.crypto.files import write_private
from ariadne.paths import Paths, ensure_private_dir

__all__ = [
    "SHELL_FILES",
    "MARK_BEGIN",
    "MARK_END",
    "Report",
    "rc_block",
    "install_rc",
    "remove_rc",
    "env_sh",
    "unit_text",
    "install",
    "remove",
]

SHELL_FILES = ("launcher.sh", "init.zsh", "init.bash")
MARK_BEGIN = "# >>> ariadne >>>"
MARK_END = "# <<< ariadne <<<"
UNIT_NAME = "ariadned.service"


@dataclass
class Report:
    done: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing


def rc_block(shell: str) -> str:
    target = f'"${{XDG_DATA_HOME:-$HOME/.local/share}}/ariadne/shell/init.{shell}"'
    return f"{MARK_BEGIN}\n[ -r {target} ] && . {target}\n{MARK_END}\n"


def _strip_block(text: str) -> tuple[str, bool]:
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    found = False
    while i < len(lines):
        if lines[i].rstrip("\r\n") == MARK_BEGIN:
            end = next((k for k in range(i + 1, len(lines)) if lines[k].rstrip("\r\n") == MARK_END), None)
            if end is not None:
                found = True
                i = end + 1
                continue
        out.append(lines[i])
        i += 1
    return "".join(out), found


def _write_keep_mode(path: Path, text: str) -> None:
    real = Path(os.path.realpath(path))
    mode = (real.stat().st_mode & 0o777) if real.exists() else 0o644
    write_private(real, text.encode(), mode=mode)


def install_rc(path: Path, shell: str) -> bool:
    """Setzt den Block ganz oben ein. Gibt ``True`` zurück, wenn die Datei geändert wurde."""
    old = path.read_text(encoding="utf-8", errors="surrogateescape") if path.exists() else ""
    rest, _ = _strip_block(old)
    new = rc_block(shell) + rest
    if new == old:
        return False
    _write_keep_mode(path, new)
    return True


def remove_rc(path: Path) -> bool:
    if not path.exists():
        return False
    old = path.read_text(encoding="utf-8", errors="surrogateescape")
    new, found = _strip_block(old)
    if found:
        _write_keep_mode(path, new)
    return found


def env_sh() -> str:
    pkg_parent = Path(ariadne.__file__).resolve().parent.parent
    return (f"ARIADNE_PYTHON={shlex.quote(sys.executable)}\n"
            f"ARIADNE_PKG_DIR={shlex.quote(str(pkg_parent))}\n"
            "ARIADNE_HOTKEY=f12\n")


def _systemd_quote(s: str) -> str:
    return f'"{s}"' if any(c.isspace() for c in s) else s


def unit_text() -> str:
    exe = _systemd_quote(sys.executable)
    return (
        "[Unit]\n"
        "Description=Ariadne Daemon (Flugschreiber für Pentests)\n\n"
        "[Service]\n"
        "Type=notify\n"
        f"ExecStart={exe} -m ariadne.daemon\n"
        "UMask=0077\n"
        "LimitCORE=0\n"
        "NoNewPrivileges=yes\n"
        "Restart=on-failure\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def _unit_path(paths: Paths) -> Path:
    return paths.config_dir.parent / "systemd" / "user" / UNIT_NAME


def _systemctl(*args: str) -> tuple[bool, str]:
    exe = shutil.which("systemctl")
    if not exe:
        return False, "systemctl nicht gefunden"
    try:
        res = subprocess.run([exe, "--user", *args], capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, type(exc).__name__
    lines = (res.stderr or res.stdout).strip().splitlines()
    return res.returncode == 0, (lines[-1] if lines else "")


def _shell_source() -> Path | None:
    try:
        src = resources.files("ariadne.shell")
    except ModuleNotFoundError:
        return None
    return Path(str(src))


def install(paths: Paths, *, rc: bool = True, systemd: bool = True, shell_src: Path | None = None) -> Report:
    rep = Report()
    shell_dir = ensure_private_dir(paths.shell_dir)
    src = shell_src if shell_src is not None else _shell_source()
    for name in SHELL_FILES:
        f = src / name if src is not None else None
        if f is None or not f.is_file():
            rep.missing.append(name)
            continue
        write_private(shell_dir / name, f.read_bytes(), mode=0o700 if name.endswith(".sh") else 0o600)
        rep.done.append(f"{name} installiert")
    write_private(shell_dir / "env.sh", env_sh().encode(), mode=0o600)
    rep.done.append("env.sh geschrieben")
    if rc:
        for shell, rcfile in (("zsh", ".zshrc"), ("bash", ".bashrc")):
            changed = install_rc(paths.home / rcfile, shell)
            rep.done.append(f"~/{rcfile}: Block {'eingetragen' if changed else 'schon aktuell'}")
    if systemd:
        unit = _unit_path(paths)
        unit.parent.mkdir(parents=True, exist_ok=True)
        write_private(unit, unit_text().encode(), mode=0o644)
        rep.done.append(f"systemd-Unit {UNIT_NAME} geschrieben")
        for args in (("daemon-reload",), ("enable", "--now", UNIT_NAME)):
            ok, msg = _systemctl(*args)
            if not ok:
                rep.warnings.append(f"systemctl --user {' '.join(args)} fehlgeschlagen: {msg}. "
                                    "Der Daemon startet dann bei Bedarf über die CLI.")
                break
    return rep


def remove(paths: Paths, *, rc: bool = True, systemd: bool = True) -> Report:
    rep = Report()
    if systemd:
        unit = _unit_path(paths)
        if unit.exists():
            ok, msg = _systemctl("disable", "--now", UNIT_NAME)
            if not ok:
                rep.warnings.append(f"systemctl --user disable fehlgeschlagen: {msg}")
            unit.unlink()
            _systemctl("daemon-reload")
            rep.done.append(f"systemd-Unit {UNIT_NAME} entfernt")
    if rc:
        for rcfile in (".zshrc", ".bashrc"):
            if remove_rc(paths.home / rcfile):
                rep.done.append(f"~/{rcfile}: Block entfernt")
    for name in (*SHELL_FILES, "env.sh"):
        p = paths.shell_dir / name
        if p.exists():
            p.unlink()
            rep.done.append(f"{name} entfernt")
    with contextlib.suppress(OSError):
        paths.shell_dir.rmdir()
    return rep
