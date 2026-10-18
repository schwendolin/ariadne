"""Zwischenablage der Kali (E111, web-api.md 18.7) mit Attrappen für xclip, xsel, wl-copy und
wl-paste in einem eigenen Ordner (keine echte Zwischenablage, kein X): Sitzung aus der eigenen
Umgebung oder aus einem gefälschten ``/proc`` (nur gleiche UID, nur grafische Sitzung), Wahl des
Werkzeugs, Wert nur über stdin, Leeren nach der Frist nur bei gleichem Inhalt, Leeren beim Ende."""

from __future__ import annotations

import asyncio
import os
import shutil
from pathlib import Path

import pytest

from ariadne.daemon.clipboard import Clipboard, ClipboardError, find_session

SECRET = "s3cr3t-Wert ü"


CAT, ENV = shutil.which("cat") or "/bin/cat", shutil.which("env") or "/usr/bin/env"


def _tool(bindir: Path, name: str, body: str) -> None:
    """Attrappe als Shell-Skript; das Werkzeug bekommt nur den Suchpfad der Tests, darum mit
    absoluten Pfaden für cat und env."""
    f = bindir / name
    f.write_text("#!/bin/sh\n" + body.replace("cat ", f"{CAT} ").replace("env ", f"{ENV} "))
    f.chmod(0o755)


def fake_tools(tmp: Path, names: tuple[str, ...] = ("xclip", "xsel", "wl-copy", "wl-paste")) -> Path:
    """Attrappen: der Inhalt liegt in ``tmp/clip``, argv und Umgebung in ``tmp/argv.log``/``env.log``."""
    bindir = tmp / "bin"
    bindir.mkdir(exist_ok=True)
    clip, argv, env = tmp / "clip", tmp / "argv.log", tmp / "env.log"
    log = f'echo "$0 $*" >> "{argv}"\nenv >> "{env}"\n'
    if "xclip" in names:
        _tool(bindir, "xclip",
              log + f'case " $* " in *" -out "*) cat "{clip}" ;; *) cat > "{clip}" ;; esac\n')
    if "xsel" in names:
        _tool(bindir, "xsel",
              log + f'case " $* " in *" --output "*) cat "{clip}" ;; *" --clear "*) : > "{clip}" ;; '
                    f'*) cat > "{clip}" ;; esac\n')
    if "wl-copy" in names:
        _tool(bindir, "wl-copy",
              log + f'case " $* " in *" --clear "*) : > "{clip}" ;; *) cat > "{clip}" ;; esac\n')
    if "wl-paste" in names:
        _tool(bindir, "wl-paste", log + f'cat "{clip}"\n')
    return bindir


def _proc(root: Path, pid: int, env: dict[str, str]) -> Path:
    d = root / str(pid)
    d.mkdir(parents=True)
    (d / "environ").write_bytes(b"\0".join(f"{k}={v}".encode() for k, v in env.items()) + b"\0")
    return d


def test_find_session_own_env_and_proc(tmp_path):
    assert find_session({"DISPLAY": ":0", "XAUTHORITY": "/home/kali/.Xauthority"}, proc_root=tmp_path) == {
        "DISPLAY": ":0", "XAUTHORITY": "/home/kali/.Xauthority"}
    proc = tmp_path / "proc"
    proc.mkdir()
    assert find_session({}, proc_root=proc) is None
    # ohne grafische Sitzung (XDG_SESSION_TYPE=tty) zählt ein Prozess nicht, auch mit DISPLAY
    _proc(proc, 10, {"DISPLAY": ":9", "XDG_SESSION_TYPE": "tty"})
    # ungültige Werte (Steuerzeichen, Shell-Zeichen) werden nie übernommen
    _proc(proc, 20, {"DISPLAY": ":0;id", "XDG_SESSION_TYPE": "x11"})
    _proc(proc, 30, {"WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "wayland",
                     "XDG_RUNTIME_DIR": "/run/user/1000", "XAUTHORITY": "/tmp/../etc/x"})
    _proc(proc, 40, {"DISPLAY": ":1", "XDG_SESSION_TYPE": "x11"})
    got = find_session({"XDG_RUNTIME_DIR": "/run/user/1"}, proc_root=proc)
    assert got == {"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/1000"}
    # nur Prozesse derselben UID
    assert find_session({}, proc_root=proc, uid=os.getuid() + 1) is None
    if os.getuid() == 0:  # als root lässt sich ein fremder Prozess nachstellen
        os.chown(proc / "30", 65534, 65534)
        assert find_session({}, proc_root=proc) == {"DISPLAY": ":1"}


def test_copy_via_stdin_clear_after_and_tool_order(tmp_path):
    bindir = fake_tools(tmp_path)

    async def scenario() -> None:
        cb = Clipboard(path=str(bindir), env={"DISPLAY": ":0"}, proc_root=tmp_path / "none",
                       clear_after_s=0.2)
        assert await cb.copy(SECRET) == "xclip"  # X11: xclip vor xsel
        assert (tmp_path / "clip").read_text() == SECRET
        assert SECRET not in (tmp_path / "argv.log").read_text()  # nie in argv
        env = (tmp_path / "env.log").read_text()
        assert "DISPLAY=:0" in env and SECRET not in env
        assert cb.pending == 1
        await asyncio.sleep(0.6)
        assert (tmp_path / "clip").read_text() == "" and cb.pending == 0
        # geänderter Inhalt bleibt stehen
        await cb.copy(SECRET)
        (tmp_path / "clip").write_text("etwas anderes")
        await asyncio.sleep(0.6)
        assert (tmp_path / "clip").read_text() == "etwas anderes"
        # Wayland: wl-copy
        wl_env = {"WAYLAND_DISPLAY": "wayland-0", "XDG_RUNTIME_DIR": "/run/user/0"}
        cbw = Clipboard(path=str(bindir), env=wl_env, proc_root=tmp_path / "none", clear_after_s=30)
        assert await cbw.copy(SECRET) == "wl-copy"
        assert (tmp_path / "clip").read_text() == SECRET
        await cbw.close()  # Ende des Daemons: sofort leeren
        assert (tmp_path / "clip").read_text() == "" and cbw.pending == 0

    asyncio.run(scenario())


def test_errors_without_tool_or_session_and_xsel_fallback(tmp_path):
    empty = tmp_path / "leer"
    empty.mkdir()

    async def scenario() -> None:
        cb = Clipboard(path=str(empty), env={"DISPLAY": ":0"}, proc_root=tmp_path)
        with pytest.raises(ClipboardError) as e:
            await cb.copy(SECRET)
        assert e.value.code == "clipboard_tool"
        (tmp_path / "w").mkdir()
        only_wl = fake_tools(tmp_path / "w", ("wl-copy",))
        cb = Clipboard(path=str(only_wl), env={"DISPLAY": ":0"}, proc_root=tmp_path / "x")
        with pytest.raises(ClipboardError) as e:
            await cb.copy(SECRET)
        assert e.value.code == "clipboard_tool"  # X11 ohne xclip/xsel
        (tmp_path / "x").mkdir()
        bindir = fake_tools(tmp_path / "x", ("xsel",))
        cb = Clipboard(path=str(bindir), env={}, proc_root=tmp_path / "keinproc")
        with pytest.raises(ClipboardError) as e:
            await cb.copy(SECRET)
        assert e.value.code == "clipboard_session"
        cb = Clipboard(path=str(bindir), env={"DISPLAY": ":0"}, proc_root=tmp_path, clear_after_s=0.1)
        assert await cb.copy(SECRET) == "xsel"
        assert (tmp_path / "x" / "clip").read_text() == SECRET
        await asyncio.sleep(0.5)
        assert (tmp_path / "x" / "clip").read_text() == ""
        with pytest.raises(ValueError):
            await cb.copy("")

    asyncio.run(scenario())


def test_values_for_copy_claim_secret_and_line_editing():
    from ariadne.daemon.core import _claim_secret_value, _is_control, _line_edit
    from ariadne.parsers.api import Obs, Ref, Span
    from tests.parsers.helpers import make_unit
    from tests.projection.helpers import apply_items, new_projector

    conn, p = new_projector()
    ident = Ref.identity("local:ip:default/192.168.56.101", "msfadmin")
    sec = Ref.secret("password", "Geheim-123")
    apply_items(p, make_unit("msfadmin:Geheim-123\n", kind="segment", context={"kind": "revshell"}),
                [Obs(ident, "identity.secret", sec, Span(0, 0))], trust="tool_text")
    p.rebuild()
    key = conn.execute("SELECT claim_key FROM claim WHERE predicate = 'identity.secret'").fetchone()[0]
    assert _claim_secret_value(conn, key) == "Geheim-123"
    other = conn.execute("SELECT claim_key FROM claim WHERE is_secret = 0 LIMIT 1").fetchone()
    assert other is None or _claim_secret_value(conn, other[0]) is None
    assert _claim_secret_value(conn, "0" * 64) is None
    assert _line_edit("passx\x7fwort\r") == "passwort"
    assert _line_edit("falsch\x15richtig\n") == "richtig"
    assert _line_edit("\x08\x08ab\r\n") == "ab"
    assert all(_is_control(ch) for ch in ("\x1b", "\x00", "\u202e", "\u200b", "\x7f", "\u2028"))
    assert not any(_is_control(ch) for ch in "aZ09 -_ü$")
