"""Zieldaten als Text (``docs/web-api.md`` 1.3, Architektur 7.7 und 9.2).

Jeder String, der aus Zieldaten stammen kann, geht durch :class:`Bag`: eigene Secrets ersetzt der
Redaktor (E72), Steuer-, Bidi-, Zero-Width- und Tag-Zeichen werden wie bei ``term_safe`` sichtbar
(``<ESC>``, ``<U+202E>``) und das Objekt bekommt ``ctrl: true``. Gekürzt wird hier nicht.

:func:`render_line` baut eine Logzeile mit verdeckten Bereichen (Secrets, eigene Secrets,
SGR-verdeckter Text) und rechnet Farbspannen und verdeckte Bereiche auf die Spalten des
ausgelieferten Texts um.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from ariadne.termsafe import visible

__all__ = [
    "MASK",
    "Bag",
    "visible_text",
    "deep_visible",
    "iso",
    "ns_str",
    "render_line",
    "encode_cursor",
    "decode_cursor",
]

MASK = "••••••••"
_SEPARATORS = {"\u2028": "<U+2028>", "\u2029": "<U+2029>"}


def visible_text(text: str) -> str:
    """Wie :func:`ariadne.termsafe.visible`, dazu Zeilen- und Absatztrenner (U+2028, U+2029)."""
    if text.isascii() and text.isprintable():
        return text  # schneller Weg: druckbares ASCII bleibt, wie es ist
    out = visible(text)
    if "\u2028" in out or "\u2029" in out:
        for ch, rep in _SEPARATORS.items():
            out = out.replace(ch, rep)
    return out


def _char_visible(ch: str) -> str:
    if " " <= ch <= "~":
        return ch
    return visible_text(ch)


class Bag:
    """Sammelt pro Objekt, ob ein Text Steuerzeichen enthielt (``ctrl``).

    ``redactor`` (optional, ``Redactor``): ersetzt eigene Secrets im Rohtext, bevor Steuerzeichen
    sichtbar werden (sonst würde ein durch Escape-Folgen zerstückeltes Secret nicht mehr erkannt).
    Der Redaktor liest dabei nur seine Muster; das ist auch im Thread der Auswertung sicher.
    """

    __slots__ = ("ctrl", "_red")

    def __init__(self, redactor: Any = None) -> None:
        self.ctrl = False
        self._red = redactor

    def __call__(self, value: Any) -> str | None:
        if value is None:
            return None
        s = value if isinstance(value, str) else str(value)
        if self._red is not None and s:
            s, _labels = self._red.redact_for_exit(s)
        out = visible_text(s)
        if out != s:
            self.ctrl = True
        return out

    def many(self, values: Iterable[Any] | None) -> list[str]:
        return [x for x in (self(v) for v in (values or ())) if x is not None]

    def new(self) -> Bag:
        """Eine frische Tasche mit demselben Redaktor (für verschachtelte Objekte)."""
        return Bag(self._red)


def deep_visible(obj: Any) -> Any:
    """Zweite Schicht vor dem Ausliefern: jeder String (auch Schlüssel) ohne Steuerzeichen."""
    if isinstance(obj, str):
        return visible_text(obj)
    if isinstance(obj, Mapping):
        return {(visible_text(k) if isinstance(k, str) else k): deep_visible(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [deep_visible(v) for v in obj]
    return obj


def iso(ns: Any) -> str | None:
    """Nanosekunden seit der Epoche als ISO-8601 in UTC mit Mikrosekunden (web-api.md 1.2)."""
    if not isinstance(ns, int) or isinstance(ns, bool) or ns <= 0:
        return None
    secs, rem = divmod(ns, 1_000_000_000)
    try:
        dt = datetime.fromtimestamp(secs, UTC).replace(microsecond=rem // 1000)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def ns_str(ns: Any) -> str | None:
    """Nanosekunden als Dezimalstring (über 2^53, web-api.md 1.2)."""
    if not isinstance(ns, int) or isinstance(ns, bool):
        return None
    return str(ns)


# --------------------------------------------------------------------------- Cursor


def encode_cursor(data: Mapping[str, Any]) -> str:
    raw = json.dumps(dict(data), separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(text: str | None) -> dict[str, Any] | None:
    """Undurchsichtiger Cursor (web-api.md 1.6). ``None`` bei leerem, ungültigem Wert: ValueError."""
    if not text:
        return None
    if len(text) > 512:
        raise ValueError("Cursor zu lang")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        data = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Cursor ungültig") from exc
    if not isinstance(data, dict):
        raise ValueError("Cursor ungültig")
    return data


# --------------------------------------------------------------------------- Logzeilen


def _merge(masks: Iterable[tuple[int, int, str]], length: int) -> list[tuple[int, int, str]]:
    """Überlappende Bereiche zusammenführen; Grenzen auf die Zeile beschränken."""
    items = sorted((max(0, a), min(length, b), k) for a, b, k in masks if b > a and a < length)
    out: list[tuple[int, int, str]] = []
    for a, b, k in items:
        if b <= a:
            continue
        if out and a <= out[-1][1]:
            pa, pb, pk = out[-1]
            out[-1] = (pa, max(pb, b), pk)
        else:
            out.append((a, b, k))
    return out


def render_line(
    text: str, masks: Sequence[tuple[int, int, str]], sgr: Sequence[Mapping[str, Any]] = ()
) -> tuple[str, bool, list[dict[str, Any]], list[dict[str, Any]]]:
    """Text einer Logzeile mit Platzhaltern für ``masks`` (Spalten ``[start, ende)`` im Rohtext,
    Art) und sichtbaren Steuerzeichen. Gibt Text, ``ctrl``, verdeckte Bereiche und Farbspannen in
    Spalten des Ergebnisses zurück."""
    merged = _merge(masks, len(text))
    colmap = [0] * (len(text) + 1)
    parts: list[str] = []
    masked: list[dict[str, Any]] = []
    ctrl = False
    pos = 0  # Spalte im Ergebnis
    i = 0
    m = 0
    while i < len(text):
        if m < len(merged) and i == merged[m][0]:
            a, b, kind = merged[m]
            for k in range(a, b):
                colmap[k] = pos
            parts.append(MASK)
            masked.append({"col_start": pos, "col_end": pos + len(MASK), "kind": kind})
            pos += len(MASK)
            i = b
            m += 1
            continue
        ch = text[i]
        out = _char_visible(ch)
        if out != ch:
            ctrl = True
        colmap[i] = pos
        parts.append(out)
        pos += len(out)
        i += 1
    colmap[len(text)] = pos
    spans: list[dict[str, Any]] = []
    for s in sgr:
        try:
            a, b = int(s["s"]), int(s["e"])
        except (KeyError, TypeError, ValueError):
            continue
        a, b = max(0, min(a, len(text))), max(0, min(b, len(text)))
        if b <= a:
            continue
        fg, bg = s.get("fg"), s.get("bg")
        spans.append(
            {
                "col_start": colmap[a],
                "col_end": colmap[b],
                "fg": fg if isinstance(fg, str) and len(fg) <= 16 else None,
                "bg": bg if isinstance(bg, str) and len(bg) <= 16 else None,
                "bold": bool(s.get("b")),
            }
        )
    return "".join(parts), ctrl, masked, spans
