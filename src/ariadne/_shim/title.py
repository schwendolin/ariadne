"""Fenstertitel des Shims (Architektur 3.6, Vertrag v0.1-Bedienung 3.5). Nur Standardbibliothek.

Der Shim fängt ``OSC 0/2`` des Kindes ab und setzt den Titel selbst zusammen.
Der Zustand steht immer vorne und stammt nur vom Shim; der innere Titel (vom Ziel
beeinflussbar) folgt nach ``|``. Jeder Bestandteil läuft durch
:func:`ariadne.termsafe.term_safe`, der ganze Titel noch einmal. Keine Emojis.

| Zustand                         | Präfix                                   |
|---------------------------------|------------------------------------------|
| Multiplexer im Vordergrund      | ``[Multiplexer: Panes nehmen auf]``      |
| ``on``                          | ``[REC lame]``                           |
| ``paused``                      | ``[PAUSE 9 min lame]`` (Projekt nur, wenn offen) |
| ``preroll``                     | ``[kein Projekt (Vorlauf 15 min)]``      |
| ``off`` oder Vorlauf 0          | ``[kein Projekt]``                       |
| ``locked`` (v1 ``waiting``)     | ``[gesperrt: ariadne start]``            |
| ``held``                        | ``[Remote lame: nicht gespeichert]``     |
| Daemon weg, verbindet, Fehler   | ``[ariadne offline]``, ``[ariadne ...]``, ``[ariadne fehler]`` |
"""

from __future__ import annotations

from ariadne.termsafe import term_safe

__all__ = ["Link", "compose_title", "osc_title", "TitleWriter", "MIN_INTERVAL", "MUX_PREFIX"]

MIN_INTERVAL = 0.2
MAX_TITLE = 200
MUX_PREFIX = "[Multiplexer: Panes nehmen auf]"


class Link:
    """Verbindungszustand aus Sicht des Titels."""

    OFFLINE = "offline"
    CONNECTING = "connecting"
    READY = "ready"
    BROKEN = "broken"


def _prefix(link: str, rec: str | None, project: str | None, *, mux: bool, pause_min: int | None,
            preroll_min: int | None, bound_slug: str | None) -> str:
    if mux:
        return MUX_PREFIX
    if link == Link.BROKEN:
        return "[ariadne fehler]"
    proj = term_safe(project, 32) if project else ""
    if rec == "paused":  # auch lokal, ohne Daemon (die Pause läuft über die Wanduhr ab)
        n = max(1, pause_min or 1)
        return f"[PAUSE {n} min {proj}]" if proj else f"[PAUSE {n} min]"
    if link == Link.OFFLINE:
        return "[ariadne offline]"
    if link == Link.CONNECTING:
        return "[ariadne ...]"
    if rec == "on":
        return f"[REC {proj}]" if proj else "[REC]"
    if rec in ("locked", "waiting"):
        return "[gesperrt: ariadne start]"
    if rec == "held":
        slug = term_safe(bound_slug, 32) if bound_slug else "?"
        return f"[Remote {slug}: nicht gespeichert]"
    if rec == "preroll" and preroll_min:
        return f"[kein Projekt (Vorlauf {int(preroll_min)} min)]"
    return "[kein Projekt]"


def compose_title(
    *,
    link: str,
    rec: str | None = None,
    project: str | None = None,
    mux: bool = False,
    pause_min: int | None = None,
    preroll_min: int | None = None,
    bound_slug: str | None = None,
    label: str | None = None,
    suggestion: bool = False,
    extra: str | None = None,
    inner: str | None = None,
    notice: str | None = None,
) -> str:
    parts = [_prefix(link, rec, project, mux=mux, pause_min=pause_min, preroll_min=preroll_min,
                     bound_slug=bound_slug)]
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
