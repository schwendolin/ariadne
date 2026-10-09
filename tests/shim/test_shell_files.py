"""Init-Dateien, Launcher und Bootstrap ohne PTY: Syntax, Kodierung, Fallbacks."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from ariadne._shim.markers import percent_decode
from tests.shim.conftest import SHELL_SRC, SRC, VENV_PY, available_shells, shell_kind

INIT = {"zsh": SHELL_SRC / "init.zsh", "bash": SHELL_SRC / "init.bash"}
TRICKY = [
    "ls -la",
    "ssh root@10.10.10.5 -p 2222",
    "echo 'ä ö ü €' ; a=b&c=d %41",
    "line1\nline2\ttab\x01ctl",
    "x" * 50 + "/~._-:@+,",
]


def run(args, **kw):
    return subprocess.run(args, capture_output=True, timeout=20, **kw)


@pytest.mark.parametrize("shell", available_shells())
def test_init_syntax(shell):
    kind = shell_kind(shell)
    assert run([shell, "-n", str(INIT[kind])]).returncode == 0


def test_launcher_syntax():
    for sh in filter(None, (shutil.which("dash"), "/bin/sh")):
        assert run([sh, "-n", str(SHELL_SRC / "launcher.sh")]).returncode == 0


@pytest.mark.parametrize("shell", available_shells())
def test_sourcing_non_interactive_is_noop(shell, tmp_path):
    kind = shell_kind(shell)
    script = tmp_path / "s"
    script.write_text(f'. "{INIT[kind]}"\necho "rc=$?"\n')
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "TERM": "xterm"}
    r = run([shell, str(script)], env=env)
    assert r.stdout.decode().strip() == "rc=0"


@pytest.mark.parametrize("shell", available_shells())
def test_encoder_matches_python_decoder(shell, tmp_path):
    kind = shell_kind(shell)
    script = tmp_path / "enc"
    if kind == "zsh":
        script.write_text(f'. "{INIT[kind]}"\n__ariadne_enc "$1"\nprint -rn -- "$REPLY"\n')
    else:
        script.write_text(f'. "{INIT[kind]}"\nLC_ALL=C\n__ariadne_enc "$1"\nprintf %s "$__ariadne_r"\n')
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "LANG": "C.UTF-8"}
    for value in TRICKY:
        r = run([shell, str(script), value], env=env)
        enc = r.stdout
        assert all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~/:@+,-%" for c in enc)
        assert percent_decode(enc) == value.encode(), (shell, value)


@pytest.mark.parametrize("shell", available_shells())
def test_var_references_resolved_without_eval(shell, tmp_path):
    kind = shell_kind(shell)
    script = tmp_path / "vars"
    out = "$REPLY" if kind == "zsh" else "$__ariadne_r"
    script.write_text(
        f'. "{INIT[kind]}"\nLC_ALL=C\nIP=10.0.0.5; arr=(a b); marker=nope\n'
        f'__ariadne_vars "$1"\nprintf %s "{out}"\n'
    )
    env = {"PATH": os.environ["PATH"], "HOME": str(tmp_path)}
    cmd = 'ssh root@$IP ${IP} ${arr} $(touch $marker) $UNSET'
    r = run([shell, str(script), cmd], env=env, cwd=tmp_path)
    assert r.stdout == b"&var.IP=10.0.0.5&var.marker=nope"
    assert not (tmp_path / "nope").exists()


# ----------------------------------------------------------------- Launcher


def fake_shell(tmp_path: Path) -> Path:
    p = tmp_path / "fakeshell"
    p.write_text('#!/bin/sh\necho "FAILED=${ARIADNE_SHIM_FAILED:-} ARGS=$*"\n')
    p.chmod(0o755)
    return p


def launcher_in(tmp_path: Path, env_sh: str | None) -> Path:
    d = tmp_path / "shell"
    d.mkdir()
    shutil.copy(SHELL_SRC / "launcher.sh", d / "launcher.sh")
    (d / "launcher.sh").chmod(0o755)
    if env_sh is not None:
        (d / "env.sh").write_text(env_sh)
    return d / "launcher.sh"


@pytest.mark.parametrize(
    "env_sh",
    [
        "ARIADNE_PYTHON=/nonexistent/python\nARIADNE_PKG_DIR=/nonexistent\n",
        None,
        "ARIADNE_PYTHON='/usr/bin/true\nif then fi\n",  # Syntaxfehler
        f"ARIADNE_PYTHON='{VENV_PY}'\nARIADNE_PKG_DIR=/nonexistent\n",
    ],
)
def test_launcher_falls_back_to_bare_shell(tmp_path, env_sh):
    launcher = launcher_in(tmp_path, env_sh)
    sh = fake_shell(tmp_path)
    r = run([str(launcher), str(sh), "-i"], env={"PATH": os.environ["PATH"]})
    assert r.returncode == 0
    assert r.stdout.decode().strip() == "FAILED=interpreter ARGS=-i"


def test_launcher_uses_shell_env_when_path_broken(tmp_path):
    launcher = launcher_in(tmp_path, "ARIADNE_PYTHON=/nonexistent\n")
    sh = fake_shell(tmp_path)
    r = run([str(launcher), "/nonexistent/zsh", "-i"], env={"PATH": os.environ["PATH"], "SHELL": str(sh)})
    assert r.stdout.decode().strip() == "FAILED=interpreter ARGS=-i"


def test_launcher_execs_interpreter_with_isolation_flags(tmp_path):
    fake_py = tmp_path / "py"
    fake_py.write_text('#!/bin/sh\necho "PY $* HOTKEY=$ARIADNE_HOTKEY"\n')
    fake_py.chmod(0o755)
    launcher = launcher_in(tmp_path, f"ARIADNE_PYTHON='{fake_py}'\nARIADNE_PKG_DIR='{SRC}'\n"
                                     "ARIADNE_HOTKEY=ctrl-]\n")
    r = run([str(launcher), "/bin/zsh", "-i"], env={"PATH": os.environ["PATH"]})
    assert r.stdout.decode().strip() == f"PY -I -S {SRC}/ariadne/_shim/__main__.py /bin/zsh -i HOTKEY=ctrl-]"


# ----------------------------------------------------------------- Bootstrap


def test_bootstrap_import_failure_execs_shell(tmp_path):
    sh = fake_shell(tmp_path)
    copy = tmp_path / "pkg" / "ariadne" / "_shim"
    copy.mkdir(parents=True)
    shutil.copy(SRC / "ariadne" / "_shim" / "__main__.py", copy / "__main__.py")
    env = {"PATH": os.environ["PATH"], "ARIADNE_PKG_DIR": str(tmp_path / "pkg")}
    r = run([str(VENV_PY), "-I", "-S", str(copy / "__main__.py"), str(sh), "-i"], env=env)
    assert r.stdout.decode().strip() == "FAILED=import ARGS=-i"


def test_bootstrap_without_tty_execs_shell(tmp_path):
    sh = fake_shell(tmp_path)
    env = {"PATH": os.environ["PATH"], "ARIADNE_PKG_DIR": str(SRC)}
    r = run([str(VENV_PY), "-I", "-S", str(SRC / "ariadne" / "_shim" / "__main__.py"), str(sh), "-i"],
            env=env, stdin=subprocess.DEVNULL)
    assert r.stdout.decode().strip() == "FAILED=notty ARGS=-i"


def test_shim_imports_only_stdlib_and_allowed_modules():
    """Mit -I -S dürfen nur Standardbibliothek und erlaubte Ariadne-Module laden."""
    code = (
        "import sys; sys.path.append(sys.argv[1]);"
        "import ariadne._shim.launch, ariadne._shim.relay, ariadne._shim.hotkeytest;"
        "mods = sorted(m for m in sys.modules if m.startswith('ariadne'));"
        "print(' '.join(mods));"
        "print('pydantic' in sys.modules)"
    )
    r = run([str(VENV_PY), "-I", "-S", "-c", code, str(SRC)])
    mods, pyd = r.stdout.decode().split("\n")[:2]
    allowed = {"ariadne", "ariadne.ids", "ariadne.paths", "ariadne.termsafe", "ariadne.ctxrules", "ariadne._shim"}
    assert pyd == "False"
    for m in mods.split():
        assert m in allowed or m.startswith("ariadne._shim."), m
