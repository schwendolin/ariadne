"""Text aus Zieldaten für die Denkanstösse: sichtbar machen, Secrets maskieren, Teile mit Kennzeichen.

Die Regel-Engine gibt Zieldaten nur so weiter, wie die Web-API sie ausliefern würde
(``docs/web-api.md`` 1.3): Steuer-, Bidi-, Zero-Width- und Tag-Zeichen sichtbar (``<ESC>``,
``<U+202E>``, wie :func:`ariadne.termsafe.visible`, dazu U+2028 und U+2029), nie gekürzt, und
bekannte Secret-Werte (Tabelle ``secret_value``) als ``••••••••``. Eigene Secrets ersetzt die Web-API
am Ausgang (``Redactor.redact_json``); die Engine sieht sie nie im Klartext ausser in Zieldaten.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any

from ariadne.termsafe import visible

__all__ = ["MASK", "vis", "Parts", "iso", "local_hm", "mask_known"]

MASK = "••••••••"
_SEPARATORS = {"\u2028": "<U+2028>", "\u2029": "<U+2029>"}


def vis(text: str) -> tuple[str, bool]:
    """Sichtbar gemachter Text und ob dabei etwas ersetzt wurde (``ctrl``)."""
    if text.isascii() and text.isprintable():
        return text, False
    out = visible(text)
    for ch, rep in _SEPARATORS.items():
        out = out.replace(ch, rep)
    return out, out != text


def mask_known(text: str, known: Sequence[str]) -> str:
    """Bekannte Secret-Werte (längste zuerst) durch :data:`MASK` ersetzen, ohne Längenangabe."""
    for s in known:
        if s and s in text:
            text = text.replace(s, MASK)
    return text


class Parts:
    """Ein Text in Teilen (``TextPart``): fester Text der Regel und Zieldaten (``target``)."""

    __slots__ = ("items", "ctrl")

    def __init__(self) -> None:
        self.items: list[tuple[str, bool]] = []
        self.ctrl = False

    def lit(self, text: str) -> Parts:
        if text:
            self.items.append((text, False))
        return self

    def target(self, value: str) -> Parts:
        shown, ctrl = vis(value)
        self.ctrl = self.ctrl or ctrl
        self.items.append((shown, True))
        return self

    def extend(self, items: Iterable[tuple[str, bool]]) -> Parts:
        for text, target in items:
            if target:
                self.target(text)
            else:
                self.lit(text)
        return self

    @property
    def text(self) -> str:
        return "".join(t for t, _ in self.items)

    def json(self) -> list[dict[str, Any]]:
        merged: list[list[Any]] = []
        for text, target in self.items:
            if merged and merged[-1][1] == target and not target:
                merged[-1][0] += text
            else:
                merged.append([text, target])
        return [{"text": t, "target": tg} for t, tg in merged]


def iso(ns: Any) -> str | None:
    """Nanosekunden als ISO-8601 in UTC mit Mikrosekunden (web-api.md 1.2)."""
    if not isinstance(ns, int) or isinstance(ns, bool) or ns <= 0:
        return None
    secs, rem = divmod(ns, 1_000_000_000)
    try:
        dt = datetime.fromtimestamp(secs, UTC).replace(microsecond=rem // 1000)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def local_hm(ns: Any) -> str | None:
    """Uhrzeit ``HH:MM`` in der Lokalzeit des Daemons (für Beleg-Labels wie «nmap -sV · 14:02»)."""
    if not isinstance(ns, int) or isinstance(ns, bool) or ns <= 0:
        return None
    try:
        return datetime.fromtimestamp(ns / 1e9).astimezone().strftime("%H:%M")
    except (OverflowError, OSError, ValueError):
        return None
