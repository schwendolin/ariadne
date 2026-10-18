"""Worker-Prozess für Screenshots unter X11 (Architektur 4.3).

Aufruf nur durch :func:`ariadne.sources.screenshot.capture`:
``python -I -m ariadne.sources.screenshot_worker MODE [X,Y,B,H]`` mit kleiner Umgebung
(``DISPLAY``, ``XAUTHORITY``). Ausgabe auf stdout: eine Zeile JSON (ASCII) mit ``mode``,
``width``, ``height``, ``dhash``, ``window_title``, ``wm_class``, danach das PNG. Bei einem Fehler
nur die JSON-Zeile ``{"error": code}`` und Exit-Code 2. Nichts auf stderr, was Zieldaten enthält.

* ``window``: aktives Fenster (``_NET_ACTIVE_WINDOW``, sonst Eingabefokus) samt Rahmen
  (``_NET_FRAME_EXTENTS``), auf den Bildschirm beschnitten.
* ``monitor``: der Monitor unter dem Mauszeiger.
* ``region``: Bereich in Bildschirmkoordinaten, auf den Bildschirm beschnitten.

Aufgenommen wird mit ``mss``; kodiert wird selbst (:func:`~ariadne.sources.screenshot.encode_png`),
das PNG hat also nie Metadaten.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from ariadne.sources.screenshot import MAX_SIDE, dhash, encode_png, parse_region


class _Fail(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


Rect = tuple[int, int, int, int]  # links, oben, breite, höhe


def _clip(rect: Rect, bounds: Rect) -> Rect | None:
    x0, y0 = max(rect[0], bounds[0]), max(rect[1], bounds[1])
    x1 = min(rect[0] + rect[2], bounds[0] + bounds[2])
    y1 = min(rect[1] + rect[3], bounds[1] + bounds[3])
    if x1 <= x0 or y1 <= y0:
        return None
    return x0, y0, min(MAX_SIDE, x1 - x0), min(MAX_SIDE, y1 - y0)


def _prop(d: Any, win: Any, name: str) -> Any:
    from Xlib import X

    try:
        p = win.get_full_property(d.intern_atom(name), X.AnyPropertyType)
    except Exception:
        return None
    return p.value if p is not None else None


def _text(value: Any) -> str | None:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    return None


def _active_window(d: Any, root: Any) -> tuple[Rect, str | None, str | None]:
    from Xlib import X

    wid = 0
    val = _prop(d, root, "_NET_ACTIVE_WINDOW")
    if val is not None and len(val):
        wid = int(val[0])
    if not wid:
        focus = d.get_input_focus().focus
        if not isinstance(focus, int) and focus != root:
            wid = focus.id
    if not wid or wid == root.id:
        raise _Fail("shot_window")
    win = d.create_resource_object("window", wid)
    try:
        attrs = win.get_attributes()
        if attrs.map_state != X.IsViewable:
            raise _Fail("shot_window")
        geom = win.get_geometry()
        pos = root.translate_coords(win, 0, 0)
    except _Fail:
        raise
    except Exception:
        raise _Fail("shot_window") from None
    left, right, top, bottom = 0, 0, 0, 0
    ext = _prop(d, win, "_NET_FRAME_EXTENTS")
    if ext is not None and len(ext) == 4 and all(0 <= int(v) <= 200 for v in ext):
        left, right, top, bottom = (int(v) for v in ext)
    rect = (pos.x - left, pos.y - top, geom.width + left + right, geom.height + top + bottom)
    title = _text(_prop(d, win, "_NET_WM_NAME"))
    if not title:
        try:
            title = _text(win.get_wm_name())
        except Exception:
            title = None
    wm_class = None
    try:
        cls = win.get_wm_class()
        if cls:
            wm_class = _text(cls[-1])
    except Exception:
        wm_class = None
    return rect, title, wm_class


def _grab(sct: Any, rect: Rect) -> tuple[bytes, int, int]:
    img = sct.grab({"left": rect[0], "top": rect[1], "width": rect[2], "height": rect[3]})
    return bytes(img.rgb), int(img.width), int(img.height)


def run(mode: str, region_arg: str | None) -> tuple[dict[str, Any], bytes]:
    import os

    import mss
    from Xlib import display as xdisplay

    disp = os.environ.get("DISPLAY") or ""
    try:
        d = xdisplay.Display(disp)
    except Exception:
        raise _Fail("shot_display") from None
    try:
        root = d.screen().root
        title = wm_class = None
        with mss.MSS(display=disp) as sct:
            mons = sct.monitors
            allb = mons[0]
            bounds: Rect = (allb["left"], allb["top"], allb["width"], allb["height"])
            if mode == "window":
                rect, title, wm_class = _active_window(d, root)
                clipped = _clip(rect, bounds)
                if clipped is None:
                    raise _Fail("shot_window")
            elif mode == "monitor":
                ptr = root.query_pointer()
                clipped = None
                for m in mons[1:] or mons:
                    r = (m["left"], m["top"], m["width"], m["height"])
                    if r[0] <= ptr.root_x < r[0] + r[2] and r[1] <= ptr.root_y < r[1] + r[3]:
                        clipped = _clip(r, bounds)
                        break
                if clipped is None:
                    m = (mons[1:] or mons)[0]
                    clipped = _clip((m["left"], m["top"], m["width"], m["height"]), bounds)
                if clipped is None:
                    raise _Fail("shot_failed")
            elif mode == "region":
                try:
                    clipped = _clip(parse_region(region_arg), bounds)
                except ValueError:
                    raise _Fail("shot_region") from None
                if clipped is None:
                    raise _Fail("shot_region")
            else:
                raise _Fail("shot_failed")
            rgb, w, h = _grab(sct, clipped)
    finally:
        d.close()
    png = encode_png(rgb, w, h)
    meta = {"mode": mode, "width": w, "height": h, "dhash": dhash(rgb, w, h),
            "window_title": title, "wm_class": wm_class}
    return meta, png


def main(argv: list[str]) -> int:
    out = sys.stdout.buffer
    mode = argv[0] if argv else ""
    region = argv[1] if len(argv) > 1 else None
    try:
        meta, png = run(mode, region)
    except _Fail as exc:
        out.write(json.dumps({"error": exc.code}).encode("ascii") + b"\n")
        out.flush()
        return 2
    except Exception:
        out.write(b'{"error": "shot_failed"}\n')
        out.flush()
        return 2
    out.write(json.dumps(meta, ensure_ascii=True).encode("ascii") + b"\n")
    out.write(png)
    out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
