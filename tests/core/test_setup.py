"""``ariadne setup``: Shell-Dateien, env.sh, RC-Blöcke, systemd-Unit (ohne echtes systemctl)."""

from __future__ import annotations

import os
import stat
import sys

import pytest

import ariadne
from ariadne.cli import setup


@pytest.fixture
def shell_src(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    for name in setup.SHELL_FILES:
        (src / name).write_text(f"# {name}\n")
    return src


@pytest.fixture
def no_systemctl(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake(*args: str) -> tuple[bool, str]:
        calls.append(args)
        return False, "kein systemd im Test"

    monkeypatch.setattr(setup, "_systemctl", fake)
    return calls


def test_install_and_remove(paths, shell_src, no_systemctl):
    zshrc = paths.home / ".zshrc"
    zshrc.write_text("export EDITOR=vim\nalias ll='ls -l'\n")
    rep = setup.install(paths, shell_src=shell_src)
    assert rep.ok and rep.warnings  # systemctl fehlgeschlagen: nur Hinweis
    sd = paths.shell_dir
    assert stat.S_IMODE(os.stat(sd).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(sd / "launcher.sh").st_mode) == 0o700
    assert stat.S_IMODE(os.stat(sd / "init.zsh").st_mode) == 0o600
    env_lines = (sd / "env.sh").read_text().splitlines()
    assert env_lines == [
        f"ARIADNE_PYTHON={sys.executable}",
        f"ARIADNE_PKG_DIR={os.path.dirname(os.path.dirname(os.path.realpath(ariadne.__file__)))}",
        "ARIADNE_HOTKEY=f12",
    ]
    text = zshrc.read_text()
    assert text.startswith(setup.rc_block("zsh")) and text.endswith("alias ll='ls -l'\n")
    assert 'init.zsh" ] && . "${XDG_DATA_HOME:-$HOME/.local/share}/ariadne/shell/init.zsh"' in text
    assert "init.bash" in (paths.home / ".bashrc").read_text()
    unit = (paths.config_dir.parent / "systemd" / "user" / "ariadned.service").read_text()
    for line in ("Type=notify", "UMask=0077", "LimitCORE=0", "NoNewPrivileges=yes", "Restart=on-failure",
                 f"ExecStart={sys.executable} -m ariadne.daemon"):
        assert line in unit
    assert ("daemon-reload",) in no_systemctl

    # idempotent
    setup.install(paths, shell_src=shell_src, systemd=False)
    assert zshrc.read_text() == text and zshrc.read_text().count(setup.MARK_BEGIN) == 1

    rep = setup.remove(paths)
    assert zshrc.read_text() == "export EDITOR=vim\nalias ll='ls -l'\n"
    assert setup.MARK_BEGIN not in (paths.home / ".bashrc").read_text()
    assert not (sd / "env.sh").exists() and not (sd / "init.zsh").exists()
    assert not (paths.config_dir.parent / "systemd" / "user" / "ariadned.service").exists()


def test_rc_block_moves_to_top_and_symlink_kept(paths, tmp_path):
    real = tmp_path / "dotfiles" / "zshrc"
    real.parent.mkdir()
    real.write_text(f"echo eins\n{setup.rc_block('zsh')}echo zwei\n")
    link = paths.home / ".zshrc"
    link.symlink_to(real)
    assert setup.install_rc(link, "zsh")
    assert link.is_symlink()
    assert real.read_text() == setup.rc_block("zsh") + "echo eins\necho zwei\n"
    assert setup.remove_rc(link) and real.read_text() == "echo eins\necho zwei\n"
    assert not setup.remove_rc(link)


def test_missing_shell_files_reported(paths, tmp_path):
    empty = tmp_path / "leer"
    empty.mkdir()
    rep = setup.install(paths, shell_src=empty, rc=False, systemd=False)
    assert not rep.ok and rep.missing == list(setup.SHELL_FILES)
    assert (paths.shell_dir / "env.sh").exists()
    assert not (paths.home / ".zshrc").exists()
