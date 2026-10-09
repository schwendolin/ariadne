"""Fenstertitel des Shims (Architektur 3.6). Nur Standardbibliothek.

Der Shim fängt ``OSC 0/2`` des Kindes ab und setzt den Titel selbst zusammen.
Der REC-Indikator steht immer vorne und stammt nur vom Shim; der innere Titel
(vom Ziel beeinflussbar) folgt nach ``|``. Jeder Bestandteil läuft durch
:func:`ariadne.termsafe.term_safe`, der ganze Titel noch einmal.
"""

from __future__ import annotations

from ariadne.termsafe import term_safe

__all__ = ["Link", "compose_title", "osc_title", "TitleWriter", "MIN_INTERVAL"]

MIN_INTERVAL = 0.2
MAX_TITLE = 200


class Link:
    """Verbindungszustand aus Sicht des Titels."""

    OFFLINE = "offline"
    CONNECTING = "connecting"
    READY = "ready"
    BROKEN = "broken"


def _prefix(link: str, rec: str | None, project: str | None, paused: bool) -> str:
    if link == Link.BROKEN:
        return "[ariadne fehler]"
    if link == Link.OFFLINE:
        return "[ariadne offline]"
    if link == Link.CONNECTING:
        return "[ariadne ...]"
    proj = term_safe(project, 32) if project else ""
    if rec == "on":
        if paused:
            return f"[REC pausiert: {proj}]" if proj else "[REC pausiert]"
        return f"[REC {proj}]" if proj else "[REC]"
    if rec == "waiting":
        return "[REC! gesperrt]"
    return f"[-- {proj}]" if proj else "[--]"


def compose_title(
    *,
    link: str,
    rec: str | None = None,
    project: str | None = None,
    paused: bool = False,
    label: str | None = None,
    suggestion: bool = False,
    extra: str | None = None,
    inner: str | None = None,
    notice: str | None = None,
) -> str:
    parts = [_prefix(link, rec, project, paused)]
    if notice:
        parts.append("ariadne: " + term_safe(notice, 80))
    else:
        if label:
            parts.append(term_safe(label, 48) + (" ?" if suggestion else ""))
        if extra:
            parts.append(term_safe(extra, 48))
    text = " ".join(parts)
    if inner:
        text += " | " + term_safe(inner, 80)
    return term_safe(text, MAX_TITLE)


def osc_title(text: str) -> bytes:
    """``OSC 2`` mit garantiert sicherem Inhalt."""
    return b"\x1b]2;" + term_safe(text, MAX_TITLE).encode("utf-8", "replace") + b"\x07"


class TitleWriter:
    """Begrenzt die Rate der Titel-Updates und unterdrückt Wiederholungen."""

    def __init__(self, interval: float = MIN_INTERVAL) -> None:
        self.interval = interval
        self.last_text: str | None = None
        self._last_t = float("-inf")
        self._pending: str | None = None

    def request(self, text: str, now: float) -> bytes | None:
        if text == self.last_text:
            self._pending = None
            return None
        if now >= self._last_t + self.interval:
            return self._write(text, now)
        self._pending = text
        return None

    def deadline(self) -> float | None:
        return None if self._pending is None else self._last_t + self.interval

    def expire(self, now: float) -> bytes | None:
        if self._pending is None or now < self._last_t + self.interval:
            return None
        text, self._pending = self._pending, None
        if text == self.last_text:
            return None
        return self._write(text, now)

    def _write(self, text: str, now: float) -> bytes:
        self._pending = None
        self.last_text = text
        self._last_t = now
        return osc_title(text)
