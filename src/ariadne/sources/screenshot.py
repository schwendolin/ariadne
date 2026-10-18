"""Screenshots unter X11 (E32, Architektur 4.3): Bausteine ohne Daemon.

* :func:`session_env` und :func:`x11_display`: Umgebung der grafischen Sitzung prüfen. Ohne
  ``DISPLAY`` gibt es :class:`ShotError` ``shot_display``, bei Wayland ``shot_wayland`` (v0.1 nur
  X11). Werte werden streng geprüft, bevor sie an einen Kindprozess gehen.
* :func:`capture`: startet den Worker (:mod:`ariadne.sources.screenshot_worker`) als eigenen
  Prozess mit kleiner Umgebung und Zeitlimit. Der Worker nimmt mit ``mss`` auf, liest die
  Fenstergeometrie mit ``python-xlib`` und kodiert das Bild selbst als kanonisches PNG.
* :func:`encode_png`, :func:`check_png`, :func:`sniff_image`, :func:`dhash`: PNG ohne Metadaten
  (nur IHDR, IDAT, IEND), Prüfung beim Speichern und Ausliefern, Erkennung nach Magic-Bytes,
  dHash für Beinahe-Duplikate.

Bilder sind Zieldaten (auf dem Bildschirm steht, was das Ziel ausgibt). Sie gehen nur als Bytes
in den Blob-Store, nie als Datei; Fenstertitel und ``WM_CLASS`` nie ins Log.

Besitzer: Teil «screenshots» (Bau v0.1-Screenshots).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import struct
import sys
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "MODES",
    "Capture",
    "ShotError",
    "SHOT_ERRORS",
    "MAX_SIDE",
    "MAX_PNG",
    "session_env",
    "x11_display",
    "capture",
    "encode_png",
    "check_png",
    "sniff_image",
    "dhash",
    "parse_region",
    "clean_text",
]

MODES = ("window", "monitor", "region")
MAX_SIDE = 16384
MAX_PNG = 64 << 20
WORKER_TIMEOUT_S = 20.0
TEXT_MAX = 300

# Feste Texte (keine Zieldaten); dieselben stehen in der Web-API und der CLI.
SHOT_ERRORS: dict[str, str] = {
    "shot_display": "Keine grafische Sitzung gefunden (DISPLAY fehlt). Am Kali-Desktop anmelden.",
    "shot_wayland": "Wayland-Sitzung: Screenshots gibt es in dieser Version nur unter X11 (Xfce).",
    "shot_window": "Kein aktives Fenster gefunden; Modus Monitor oder Bereich wählen.",
    "shot_region": "Der Bereich liegt ausserhalb des Bildschirms.",
    "shot_failed": "Screenshot fehlgeschlagen.",
}

_DISPLAY_RE = re.compile(r"^[A-Za-z0-9._/-]{0,200}:[0-9]{1,5}(\.[0-9]{1,3})?$")
_WAYLAND_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+-]{0,255}$")
_SESSION_TYPES = frozenset({"x11", "wayland", "tty", "mir", "unspecified"})
SESSION_KEYS = ("DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE")
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")

PNG_SIG = b"\x89PNG\r\n\x1a\n"


class ShotError(Exception):
    """``code`` aus :data:`SHOT_ERRORS`; die Meldung ist immer der feste Text."""

    def __init__(self, code: str) -> None:
        if code not in SHOT_ERRORS:
            code = "shot_failed"
        super().__init__(SHOT_ERRORS[code])
        self.code = code


@dataclass(frozen=True)
class Capture:
    png: bytes
    mode: str
    width: int
    height: int
    dhash: str | None
    window_title: str | None
    wm_class: str | None
    backend: str = "mss+xlib"


# --------------------------------------------------------------------------- #
# Sitzung
# --------------------------------------------------------------------------- #


def session_env(env: Mapping[str, Any] | None) -> dict[str, str]:
    """Nur gültige Sitzungsvariablen (Rest fällt still weg)."""
    out: dict[str, str] = {}
    if not env:
        return out
    disp = env.get("DISPLAY")
    if isinstance(disp, str) and _DISPLAY_RE.match(disp):
        out["DISPLAY"] = disp
    way = env.get("WAYLAND_DISPLAY")
    if isinstance(way, str) and _WAYLAND_RE.match(way):
        out["WAYLAND_DISPLAY"] = way
    for key in ("XAUTHORITY", "XDG_RUNTIME_DIR"):
        v = env.get(key)
        if isinstance(v, str) and _PATH_RE.match(v) and ".." not in v.split("/"):
            out[key] = v
    st = env.get("XDG_SESSION_TYPE")
    if isinstance(st, str) and st in _SESSION_TYPES:
        out["XDG_SESSION_TYPE"] = st
    return out


def x11_display(env: Mapping[str, str]) -> str:
    """``DISPLAY`` einer X11-Sitzung, sonst :class:`ShotError`.

    Wayland (auch mit XWayland, das nur X-Fenster sähe) ist in v0.1 nicht unterstützt, ausser
    ``XDG_SESSION_TYPE`` sagt ausdrücklich ``x11``."""
    st = env.get("XDG_SESSION_TYPE")
    disp = env.get("DISPLAY")
    if st == "wayland" or (env.get("WAYLAND_DISPLAY") and st != "x11"):
        raise ShotError("shot_wayland")
    if not disp:
        raise ShotError("shot_display")
    return disp


def parse_region(value: Any) -> tuple[int, int, int, int]:
    """``[x, y, w, h]``, ``{x, y, width, height}`` oder ``"x,y,w,h"`` -> Tupel; sonst ``ValueError``."""
    if isinstance(value, str):
        parts: list[Any] = value.split(",")
        try:
            parts = [int(p.strip()) for p in parts]
        except ValueError:
            raise ValueError("region") from None
    elif isinstance(value, Mapping):
        parts = [value.get("x"), value.get("y"), value.get("width"), value.get("height")]
    elif isinstance(value, list | tuple):
        parts = list(value)
    else:
        raise ValueError("region")
    if len(parts) != 4 or not all(type(p) is int for p in parts):
        raise ValueError("region")
    x, y, w, h = parts
    if not (0 <= x <= 65535 and 0 <= y <= 65535 and 1 <= w <= MAX_SIDE and 1 <= h <= MAX_SIDE):
        raise ValueError("region")
    return x, y, w, h


def clean_text(value: Any) -> str | None:
    """Fenstertitel und ``WM_CLASS`` aus dem X-Server: begrenzt, Steuerzeichen als Leerzeichen."""
    if not isinstance(value, str) or not value:
        return None
    return _CTRL.sub(" ", value)[:TEXT_MAX]


# --------------------------------------------------------------------------- #
# PNG
# --------------------------------------------------------------------------- #


def _chunk(kind: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(kind + data) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)


def encode_png(rgb: bytes, width: int, height: int, *, level: int = 6) -> bytes:
    """Kanonisches PNG (RGB, 8 Bit, ohne Filter, ohne Metadaten): nur IHDR, IDAT, IEND."""
    if not (1 <= width <= MAX_SIDE and 1 <= height <= MAX_SIDE) or len(rgb) != width * height * 3:
        raise ValueError("Bildgrösse passt nicht")
    stride = width * 3
    mv = memoryview(rgb)
    raw = b"".join(b"\x00" + mv[y * stride:(y + 1) * stride].tobytes() for y in range(height))
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return PNG_SIG + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", zlib.compress(raw, level)) + _chunk(b"IEND", b"")


def check_png(data: bytes) -> tuple[int, int]:
    """Prüft ein PNG, wie Ariadne es schreibt: Signatur, CRCs, nur IHDR, IDAT, IEND (also keine
    Metadaten wie tEXt, eXIf, iCCP), 8 Bit RGB oder RGBA, ohne Interlace, nichts nach IEND.
    Gibt ``(breite, höhe)`` zurück, sonst ``ValueError``."""
    if len(data) > MAX_PNG or not data.startswith(PNG_SIG):
        raise ValueError("kein PNG")
    pos = len(PNG_SIG)
    size: tuple[int, int] | None = None
    seen_idat = False
    while True:
        if pos + 12 > len(data):
            raise ValueError("PNG abgeschnitten")
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        kind = data[pos + 4:pos + 8]
        end = pos + 8 + length
        if length > MAX_PNG or end + 4 > len(data):
            raise ValueError("PNG abgeschnitten")
        body = data[pos + 8:end]
        (crc,) = struct.unpack(">I", data[end:end + 4])
        if zlib.crc32(kind + body) & 0xFFFFFFFF != crc:
            raise ValueError("PNG-Prüfsumme falsch")
        pos = end + 4
        if size is None:
            if kind != b"IHDR" or length != 13:
                raise ValueError("IHDR fehlt")
            w, h, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", body)
            if not (1 <= w <= MAX_SIDE and 1 <= h <= MAX_SIDE) or depth != 8 or ctype not in (2, 6) \
                    or comp or filt or inter:
                raise ValueError("IHDR nicht kanonisch")
            size = (w, h)
        elif kind == b"IDAT":
            seen_idat = True
        elif kind == b"IEND":
            if length or not seen_idat or pos != len(data):
                raise ValueError("IEND nicht am Ende")
            return size
        else:
            raise ValueError("PNG mit Zusatzdaten")


def sniff_image(data: bytes) -> str | None:
    """MIME-Typ nach Magic-Bytes: nur ``image/png``, ``image/jpeg``, ``image/webp``; sonst ``None``
    (also nie SVG, HTML oder GIF)."""
    if data.startswith(PNG_SIG):
        return "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if len(data) >= 16 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def dhash(rgb: bytes, width: int, height: int) -> str | None:
    """Differenz-Hash (64 Bit, 16 Hex-Zeichen) über ein 9x8-Raster aus Graustufen; jede Zelle ist
    der Mittelwert von 4x4 Stichproben. ``None`` bei leeren Bildern."""
    if width < 1 or height < 1 or len(rgb) < width * height * 3:
        return None
    cells: list[list[float]] = []
    for gy in range(8):
        row: list[float] = []
        for gx in range(9):
            acc = 0.0
            for sy in range(4):
                y = min(height - 1, int((gy + (sy + 0.5) / 4) * height / 8))
                for sx in range(4):
                    x = min(width - 1, int((gx + (sx + 0.5) / 4) * width / 9))
                    i = (y * width + x) * 3
                    acc += 0.299 * rgb[i] + 0.587 * rgb[i + 1] + 0.114 * rgb[i + 2]
            row.append(acc / 16)
        cells.append(row)
    bits = 0
    for row in cells:
        for x in range(8):
            bits = (bits << 1) | (1 if row[x] > row[x + 1] else 0)
    return f"{bits:016x}"


# --------------------------------------------------------------------------- #
# Worker
# --------------------------------------------------------------------------- #


def _worker_env(env: Mapping[str, str], display: str) -> dict[str, str]:
    out = {
        "PATH": os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "HOME": os.environ.get("HOME") or "/",
        "LANG": "C.UTF-8",
        "DISPLAY": display,
    }
    if env.get("XAUTHORITY"):
        out["XAUTHORITY"] = env["XAUTHORITY"]
    return out


async def capture(env: Mapping[str, str], mode: str, region: tuple[int, int, int, int] | None = None,
                  *, timeout: float = WORKER_TIMEOUT_S, python: str | None = None) -> Capture:
    """Nimmt im Worker-Prozess auf. ``env`` ist schon durch :func:`session_env` gegangen."""
    if mode not in MODES:
        raise ValueError("mode")
    if (mode == "region") != (region is not None):
        raise ValueError("region")
    display = x11_display(env)
    argv = [python or sys.executable, "-I", "-m", "ariadne.sources.screenshot_worker", mode]
    if region is not None:
        argv.append(",".join(str(v) for v in region))
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=_worker_env(env, display), start_new_session=True,
        )
    except OSError:
        raise ShotError("shot_failed") from None
    try:
        out = await asyncio.wait_for(_read_capped(proc), timeout)
        rc = await asyncio.wait_for(proc.wait(), 5)
    except (TimeoutError, ValueError):
        await _kill(proc)
        raise ShotError("shot_failed") from None
    except BaseException:  # Abbruch (Daemon endet): keinen Worker zurücklassen
        await asyncio.shield(_kill(proc))
        raise
    return _parse_output(out, rc)


async def _kill(proc: asyncio.subprocess.Process) -> None:
    with contextlib.suppress(ProcessLookupError):
        proc.kill()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(proc.wait(), 5)


async def _read_capped(proc: asyncio.subprocess.Process) -> bytes:
    assert proc.stdout is not None
    buf = bytearray()
    while True:
        chunk = await proc.stdout.read(1 << 20)
        if not chunk:
            return bytes(buf)
        buf += chunk
        if len(buf) > MAX_PNG + 65536:
            raise ValueError("zu gross")


def _parse_output(out: bytes, rc: int | None) -> Capture:
    head, sep, png = out.partition(b"\n")
    try:
        meta = json.loads(head.decode("ascii")) if sep and len(head) <= 8192 else None
    except (UnicodeDecodeError, ValueError):
        meta = None
    if not isinstance(meta, dict):
        raise ShotError("shot_failed")
    err = meta.get("error")
    if rc != 0 or err is not None:
        raise ShotError(err if isinstance(err, str) else "shot_failed")
    try:
        w, h = check_png(png)
    except ValueError:
        raise ShotError("shot_failed") from None
    mode = meta.get("mode")
    if mode not in MODES or meta.get("width") != w or meta.get("height") != h:
        raise ShotError("shot_failed")
    dh = meta.get("dhash")
    if not (isinstance(dh, str) and re.fullmatch(r"[0-9a-f]{16}", dh)):
        dh = None
    return Capture(png=png, mode=mode, width=w, height=h, dhash=dh,
                   window_title=clean_text(meta.get("window_title")),
                   wm_class=clean_text(meta.get("wm_class")))
