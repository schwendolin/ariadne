"""Fixtures für Screenshots: eigener X-Server (Xvfb) mit freier Display-Nummer, Fenster mit
bekannter Farbe und Titel, kleiner PNG-Dekoder. Läuft auch unter ``xvfb-run`` (der eigene
X-Server ist dann zusätzlich da). Ohne Xvfb werden die Tests mit echter Aufnahme übersprungen."""

from __future__ import annotations

import contextlib
import os
import shutil
import struct
import subprocess
import zlib
from collections.abc import Iterator
from dataclasses import dataclass

import pytest

from tests.core.conftest import operator, operator_template, paths, xdg  # noqa: F401

W, H = 800, 600


@dataclass
class XServer:
    display: str
    proc: subprocess.Popen[bytes]


@pytest.fixture(scope="session")
def xserver() -> Iterator[XServer]:
    exe = shutil.which("Xvfb")
    if exe is None:
        pytest.skip("Xvfb fehlt")
    r, w = os.pipe()
    proc = subprocess.Popen(
        [exe, "-displayfd", str(w), "-screen", "0", f"{W}x{H}x24", "-nolisten", "tcp", "-noreset"],
        pass_fds=(w,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
    )
    os.close(w)
    buf = b""
    with os.fdopen(r, "rb") as fh:
        while not buf.endswith(b"\n"):
            ch = fh.read(1)
            if not ch:
                break
            buf += ch
    if not buf.strip().isdigit():
        proc.kill()
        proc.wait()
        pytest.skip("Xvfb startete nicht")
    try:
        yield XServer(f":{int(buf)}", proc)
    finally:
        proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(5)
        if proc.poll() is None:
            proc.kill()
            proc.wait()


class Window:
    """Ein Fenster mit fester Farbe; setzt ``_NET_ACTIVE_WINDOW`` auf der Wurzel (es gibt keinen
    Fenstermanager, der das sonst täte)."""

    def __init__(self, display: str, *, x: int, y: int, w: int, h: int, rgb: tuple[int, int, int],
                 title: str, wm_class: str = "ariadne-test") -> None:
        from Xlib import X, Xatom
        from Xlib import display as xdisplay

        self.d = xdisplay.Display(display)
        scr = self.d.screen()
        root = scr.root
        pixel = (rgb[0] << 16) | (rgb[1] << 8) | rgb[2]
        self.win = root.create_window(x, y, w, h, 0, scr.root_depth, X.InputOutput, X.CopyFromParent,
                                      background_pixel=pixel, override_redirect=True)
        self.win.set_wm_name(title)
        utf8 = self.d.intern_atom("UTF8_STRING")
        self.win.change_property(self.d.intern_atom("_NET_WM_NAME"), utf8, 8, title.encode("utf-8"))
        self.win.set_wm_class(wm_class, wm_class.capitalize())
        self.win.map()
        root.change_property(self.d.intern_atom("_NET_ACTIVE_WINDOW"), Xatom.WINDOW, 32, [self.win.id])
        self.d.sync()
        self.win.clear_area(0, 0, w, h)
        self.d.sync()

    def close(self) -> None:
        from Xlib import Xatom

        root = self.d.screen().root
        root.change_property(self.d.intern_atom("_NET_ACTIVE_WINDOW"), Xatom.WINDOW, 32, [0])
        self.win.destroy()
        self.d.sync()
        self.d.close()


@pytest.fixture
def window(xserver: XServer) -> Iterator[Window]:
    w = Window(xserver.display, x=100, y=50, w=200, h=120, rgb=(200, 30, 40),
               title="root@target: \x1b]0;evil\x07 /tmp")
    try:
        yield w
    finally:
        w.close()


def decode_png(data: bytes) -> tuple[int, int, bytes]:
    """Dekoder nur für Ariadnes kanonisches PNG (RGB, 8 Bit, Filter 0)."""
    assert data[:8] == b"\x89PNG\r\n\x1a\n"
    pos, idat, w, h = 8, b"", 0, 0
    while pos < len(data):
        (n,) = struct.unpack(">I", data[pos:pos + 4])
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + n]
        if kind == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
            assert depth == 8 and ctype == 2
        elif kind == b"IDAT":
            idat += body
        pos += 12 + n
    raw = zlib.decompress(idat)
    stride = w * 3
    rows = []
    for y in range(h):
        line = raw[y * (stride + 1):(y + 1) * (stride + 1)]
        assert line[0] == 0
        rows.append(line[1:])
    return w, h, b"".join(rows)


def pixel(img: tuple[int, int, bytes], x: int, y: int) -> tuple[int, ...]:
    w, _h, rgb = img
    i = (y * w + x) * 3
    return tuple(rgb[i:i + 3])
