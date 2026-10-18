"""Bausteine der Screenshots: kanonisches PNG, Prüfung, Erkennung, dHash, Sitzung; echte Aufnahme
im Worker gegen einen eigenen Xvfb (Fenster, Monitor, Bereich, Fehler)."""

from __future__ import annotations

import asyncio
import struct
import zlib

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne.sources import screenshot as shot
from tests.screenshots.conftest import H, W, decode_png, pixel


def _chunk(kind: bytes, body: bytes) -> bytes:
    return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))


def test_encode_png_is_canonical_and_roundtrips():
    rgb = bytes(range(256)) * 3  # 16 x 16 Pixel
    png = shot.encode_png(rgb[: 16 * 16 * 3], 16, 16)
    assert shot.check_png(png) == (16, 16)
    assert decode_png(png) == (16, 16, rgb[: 16 * 16 * 3])
    assert b"tEXt" not in png and b"eXIf" not in png and b"tIME" not in png
    assert shot.encode_png(rgb[: 16 * 16 * 3], 16, 16) == png  # deterministisch
    with pytest.raises(ValueError):
        shot.encode_png(b"\x00" * 5, 2, 2)


def test_check_png_rejects_metadata_and_damage():
    png = shot.encode_png(b"\x10" * 12, 2, 2)
    iend = png.rindex(b"IEND") - 4
    with_text = png[:iend] + _chunk(b"tEXt", b"Comment\x00hallo") + png[iend:]
    with_exif = png[:33] + _chunk(b"eXIf", b"MM\x00*") + png[33:]
    broken_crc = png[:20] + b"\xff" + png[21:]
    for bad in (with_text, with_exif, png + b"x", png[:-1], b"GIF89a" + png[6:], broken_crc):
        with pytest.raises(ValueError):
            shot.check_png(bad)
    # 16 Bit, Interlace, Palette: nicht kanonisch
    ihdr = struct.pack(">IIBBBBB", 2, 2, 16, 2, 0, 0, 0)
    with pytest.raises(ValueError):
        shot.check_png(shot.PNG_SIG + _chunk(b"IHDR", ihdr) + png[33:])


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=300))
def test_check_png_never_crashes_on_garbage(data):
    for blob in (data, shot.PNG_SIG + data):
        try:
            shot.check_png(blob)
        except ValueError:
            pass


def test_sniff_image_only_png_jpeg_webp():
    assert shot.sniff_image(shot.encode_png(b"\x00" * 3, 1, 1)) == "image/png"
    assert shot.sniff_image(b"\xff\xd8\xff\xe0" + b"\x00" * 20) == "image/jpeg"
    assert shot.sniff_image(b"RIFF\x10\x00\x00\x00WEBPVP8 " + b"\x00" * 8) == "image/webp"
    for other in (b"<svg xmlns='http://www.w3.org/2000/svg'/>", b"<?xml version='1.0'?><svg/>",
                  b"GIF89a\x01\x00", b"<html>", b"", b"RIFF\x00\x00\x00\x00WAVEfmt "):
        assert shot.sniff_image(other) is None


def test_dhash_stable_and_sensitive():
    w, h = 90, 80
    grad = bytes(v for y in range(h) for x in range(w) for v in (x * 2, x * 2, x * 2))
    flat = b"\x80" * (w * h * 3)
    a = shot.dhash(grad, w, h)
    assert a is not None and len(a) == 16 and a == shot.dhash(grad, w, h)
    assert shot.dhash(flat, w, h) == "0" * 16
    rev = bytes(v for y in range(h) for x in range(w) for v in (255 - x * 2,) * 3)
    assert shot.dhash(rev, w, h) == "f" * 16 and a == "0" * 16


def test_parse_region_and_session_env():
    assert shot.parse_region("1, 2,3,4") == (1, 2, 3, 4)
    assert shot.parse_region({"x": 0, "y": 0, "width": 5, "height": 6}) == (0, 0, 5, 6)
    for bad in ("1,2,3", "a,b,c,d", [0, 0, 0, 5], [0, 0, 5, True], [-1, 0, 5, 5], [0, 0, 20000, 5], None):
        with pytest.raises(ValueError):
            shot.parse_region(bad)
    env = shot.session_env({"DISPLAY": ":0; rm -rf /", "XAUTHORITY": "/home/k/../../etc/shadow",
                            "WAYLAND_DISPLAY": "wayland-0", "XDG_SESSION_TYPE": "evil", "PATH": "/x"})
    assert env == {"WAYLAND_DISPLAY": "wayland-0"}
    assert shot.session_env({"DISPLAY": ":1", "XAUTHORITY": "/home/kali/.Xauthority"}) == {
        "DISPLAY": ":1", "XAUTHORITY": "/home/kali/.Xauthority"}


def test_x11_display_clear_messages():
    with pytest.raises(shot.ShotError) as e:
        shot.x11_display({})
    assert e.value.code == "shot_display" and "DISPLAY" in str(e.value)
    with pytest.raises(shot.ShotError) as e:
        shot.x11_display({"WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"})
    assert e.value.code == "shot_wayland" and "X11" in str(e.value)
    with pytest.raises(shot.ShotError) as e:
        shot.x11_display({"XDG_SESSION_TYPE": "wayland", "DISPLAY": ":0"})
    assert e.value.code == "shot_wayland"
    assert shot.x11_display({"XDG_SESSION_TYPE": "x11", "WAYLAND_DISPLAY": "w", "DISPLAY": ":3"}) == ":3"
    assert shot.ShotError("unbekannt").code == "shot_failed"


def test_clean_text_bounds_and_controls():
    assert shot.clean_text("a\x1b]0;x\x07b‮c") == "a ]0;x b c"
    assert len(shot.clean_text("x" * 1000) or "") == shot.TEXT_MAX
    assert shot.clean_text("") is None and shot.clean_text(5) is None


# --------------------------------------------------------------------------- #
# Echte Aufnahme (Xvfb)
# --------------------------------------------------------------------------- #


def test_capture_window_monitor_region(xserver, window):
    env = {"DISPLAY": xserver.display}

    cap = asyncio.run(shot.capture(env, "window"))
    assert (cap.mode, cap.width, cap.height) == ("window", 200, 120)
    assert cap.window_title == "root@target:  ]0;evil  /tmp"  # Steuerzeichen als Leerzeichen
    assert cap.wm_class == "Ariadne-test" and cap.backend == "mss+xlib"
    img = decode_png(cap.png)
    assert pixel(img, 0, 0) == (200, 30, 40) and pixel(img, 199, 119) == (200, 30, 40)
    assert shot.check_png(cap.png) == (200, 120)

    cap = asyncio.run(shot.capture(env, "monitor"))
    assert (cap.mode, cap.width, cap.height) == ("monitor", W, H)
    img = decode_png(cap.png)
    assert pixel(img, 150, 100) == (200, 30, 40) and pixel(img, 10, 10) != (200, 30, 40)
    assert cap.window_title is None and cap.dhash is not None

    cap = asyncio.run(shot.capture(env, "region", (90, 40, 30, 20)))
    assert (cap.width, cap.height) == (30, 20)
    img = decode_png(cap.png)
    assert pixel(img, 0, 0) != (200, 30, 40) and pixel(img, 29, 19) == (200, 30, 40)

    # über den Rand hinaus: beschnitten; ganz ausserhalb: klare Meldung
    cap = asyncio.run(shot.capture(env, "region", (W - 10, H - 10, 100, 100)))
    assert (cap.width, cap.height) == (10, 10)
    with pytest.raises(shot.ShotError) as e:
        asyncio.run(shot.capture(env, "region", (W + 5, 0, 10, 10)))
    assert e.value.code == "shot_region"


def test_capture_without_active_window_and_bad_display(xserver):
    with pytest.raises(shot.ShotError) as e:
        asyncio.run(shot.capture({"DISPLAY": xserver.display}, "window"))
    assert e.value.code == "shot_window"
    with pytest.raises(shot.ShotError) as e:
        asyncio.run(shot.capture({"DISPLAY": ":4711"}, "monitor"))  # kein X-Server dort
    assert e.value.code in ("shot_display", "shot_failed")
    with pytest.raises(shot.ShotError) as e:
        asyncio.run(shot.capture({}, "monitor"))
    assert e.value.code == "shot_display"
    with pytest.raises(ValueError):
        asyncio.run(shot.capture({"DISPLAY": xserver.display}, "region"))
