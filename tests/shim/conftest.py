"""Hilfen für Shim-Tests: isoliertes HOME mit installierter Shell-Integration."""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SRC = REPO / "src"
SHELL_SRC = SRC / "ariadne" / "shell"
VENV_PY = Path(sys.executable)
PROMPT = "PRMT> "

RC_LINES = (
    "# >>> ariadne >>>\n"
    '[ -r "${{XDG_DATA_HOME:-$HOME/.local/share}}/ariadne/shell/init.{sh}" ] && '
    '. "${{XDG_DATA_HOME:-$HOME/.local/share}}/ariadne/shell/init.{sh}"\n'
    "# <<< ariadne <<<\n"
)
# Wie Kali: precmd setzt den Fenstertitel per OSC 0.
ZSHRC_EXTRA = f"PS1='{PROMPT}'\nprecmd() {{ print -Pn '\\e]0;%n@%m: %~\\a' }}\nHISTFILE=~/.zsh_history\n"
BASHRC_EXTRA = f"PS1='\\[\\e]0;\\u@\\h: \\w\\a\\]{PROMPT}'\nHISTFILE=~/.bash_history\n"


def available_shells() -> list[str]:
    """zsh und bash aus PATH, dazu ``ARIADNE_TEST_EXTRA_SHELLS`` (Pfade, mit ``:`` getrennt)."""
    out = [p for p in (shutil.which("zsh"), shutil.which("bash")) if p]
    for extra in filter(None, os.environ.get("ARIADNE_TEST_EXTRA_SHELLS", "").split(":")):
        if os.access(extra, os.X_OK):
            out.append(extra)
    return out


def shell_kind(path: str) -> str:
    return "zsh" if os.path.basename(path).startswith("zsh") else "bash"


@dataclass
class Box:
    base: Path
    home: Path
    shell_dir: Path
    run_dir: Path
    env: dict[str, str]

    @property
    def sock(self) -> Path:
        return self.run_dir / "ariadne" / "term.sock"


def make_box(base: Path, *, python: str | os.PathLike = VENV_PY, pkg: str | os.PathLike = SRC,
             hotkey: str = "f12", shell: str = "/bin/sh", env_sh: str | None = None) -> Box:
    home = base / "h"
    shell_dir = home / ".local" / "share" / "ariadne" / "shell"
    shell_dir.mkdir(parents=True)
    for name in ("launcher.sh", "init.zsh", "init.bash"):
        shutil.copy(SHELL_SRC / name, shell_dir / name)
    (shell_dir / "launcher.sh").chmod(0o755)
    if env_sh is None:
        env_sh = f"ARIADNE_PYTHON='{python}'\nARIADNE_PKG_DIR='{pkg}'\nARIADNE_HOTKEY='{hotkey}'\n"
    (shell_dir / "env.sh").write_text(env_sh)
    (home / ".zshrc").write_text(RC_LINES.format(sh="zsh") + ZSHRC_EXTRA)
    (home / ".bashrc").write_text(RC_LINES.format(sh="bash") + BASHRC_EXTRA)
    run_dir = base / "r"
    run_dir.mkdir(mode=0o700)
    env = {
        "HOME": str(home),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": str(run_dir),
        "SHELL": shell,
    }
    return Box(base, home, shell_dir, run_dir, env)


@pytest.fixture
def box_factory(tmp_path_factory):
    def make(**kw) -> Box:
        return make_box(tmp_path_factory.mktemp("b"), **kw)

    return make
