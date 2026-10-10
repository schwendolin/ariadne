"""Pfade nach XDG. Nur Standardbibliothek, wird auch vom Shim importiert.

Architektur 3.7, 4.1, 8.6: Sockets im Runtime-Ordner, nie in ``/tmp``.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Paths", "default_paths", "ensure_private_dir", "UnsafePathError"]


class UnsafePathError(RuntimeError):
    """Ein Ordner gehört nicht dem Benutzer, ist ein Symlink oder zu offen."""


@dataclass(frozen=True)
class Paths:
    home: Path
    config_dir: Path  # ~/.config/ariadne
    data_dir: Path  # ~/.local/share/ariadne
    state_dir: Path  # ~/.local/state/ariadne
    runtime_dir: Path  # $XDG_RUNTIME_DIR/ariadne oder ~/.local/state/ariadne/run
    projects_root: Path  # ~/ariadne

    @property
    def term_sock(self) -> Path:
        return self.runtime_dir / "term.sock"

    @property
    def ctl_sock(self) -> Path:
        return self.runtime_dir / "ctl.sock"

    @property
    def work_dir(self) -> Path:
        """tmpfs-Ordner für Klartext-Arbeitsdateien (Architektur 8.4)."""
        return self.runtime_dir / "work"

    @property
    def operator_dir(self) -> Path:
        return self.data_dir / "operator"

    @property
    def shell_dir(self) -> Path:
        """Installierte Shell-Integration und Launcher."""
        return self.data_dir / "shell"

    @property
    def registry_file(self) -> Path:
        return self.state_dir / "registry.json"

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.toml"

    @property
    def daemon_log(self) -> Path:
        """Log des abgekoppelt gestarteten Daemons (nur Metadaten, nie Inhalte)."""
        return self.state_dir / "ariadned.log"

    @property
    def disable_file(self) -> Path:
        """Existiert diese Datei, startet der Shim nicht (Notausgang)."""
        return self.config_dir / "disable"


def default_paths(env: Mapping[str, str] | None = None) -> Paths:
    env = os.environ if env is None else env
    home = Path(env.get("HOME") or Path.home())
    config_home = Path(env.get("XDG_CONFIG_HOME") or home / ".config")
    data_home = Path(env.get("XDG_DATA_HOME") or home / ".local" / "share")
    state_home = Path(env.get("XDG_STATE_HOME") or home / ".local" / "state")
    runtime = env.get("XDG_RUNTIME_DIR")
    state_dir = state_home / "ariadne"
    runtime_dir = Path(runtime) / "ariadne" if runtime else state_dir / "run"
    projects_root = Path(env.get("ARIADNE_PROJECTS_ROOT") or home / "ariadne")
    return Paths(
        home=home,
        config_dir=config_home / "ariadne",
        data_dir=data_home / "ariadne",
        state_dir=state_dir,
        runtime_dir=runtime_dir,
        projects_root=projects_root,
    )


def ensure_private_dir(path: Path, mode: int = 0o700) -> Path:
    """Legt einen Ordner mit Rechten 0700 an und prüft ihn.

    Wirft :class:`UnsafePathError`, wenn der Ordner ein Symlink ist, einem
    anderen Benutzer gehört oder Gruppe/Andere Rechte haben.
    """
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise UnsafePathError(f"kein echter Ordner: {path}")
    if st.st_uid != os.getuid():
        raise UnsafePathError(f"gehört nicht dem Benutzer: {path}")
    if st.st_mode & 0o077:
        os.chmod(path, mode)
        st = os.lstat(path)
        if st.st_mode & 0o077:
            raise UnsafePathError(f"Rechte zu offen: {path}")
    return path
