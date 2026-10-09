"""Mini-Prompt des Shims (Architektur 3.4). Nur Standardbibliothek.

Eine eigene Zeile wie ssh ``~C``, nur im normalen Bildschirm. Gefragt wird nur
nach Host, Benutzer, Tastenwahl oder einer Notiz, **nie** nach Secrets: ein
Ziel kann eine gefälschte Ariadne-Zeile ausgeben.

Ablauf: Der Shim fragt per ``CSI 6n`` die Cursorposition ab, schreibt einen
Zeilenumbruch und den Prompt. Die Antwort des Terminals kommt über stdin und
wird hier abgefangen. Beim Schliessen löscht der Prompt seine Zeile und setzt
den Cursor zurück; ohne Antwort bleibt der Cursor auf der leeren Zeile.
Alles Angezeigte läuft durch :func:`~ariadne.termsafe.term_safe`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from ariadne.termsafe import term_safe

__all__ = ["LinePrompt", "HOST_CHARS", "common_prefix", "parse_user_host"]

HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:@[]%/")
MAX_COMPLETIONS = 500
_CPR = re.compile(rb"\x1b\[(\d{1,4});(\d{1,4})R")
_SEQ = re.compile(
    rb"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    rb"|\x1b[\]P_^X][^\x07\x1b]*(?:\x07|\x1b\\)"  # Strings
    rb"|\x1bO."  # SS3 (Pfeiltasten, F1-F4)
    rb"|\x1b[ -~]"  # Alt+Taste
)


def common_prefix(items: Iterable[str]) -> str:
    items = list(items)
    if not items:
        return ""
    lo, hi = min(items), max(items)
    i = 0
    while i < len(lo) and lo[i] == hi[i]:
        i += 1
    return lo[:i]


def parse_user_host(text: str) -> tuple[str | None, str | None]:
    """``user@host`` oder ``host``. Leere Teile ergeben ``None``."""
    text = text.strip()
    if "@" in text:
        user, host = text.rsplit("@", 1)
        return (user or None), (host or None)
    return None, (text or None)


class LinePrompt:
    """Einzeiliger Prompt. ``mode``: ``line`` (Text), ``choice`` (eine Taste), ``message``."""

    def __init__(
        self,
        label: str,
        *,
        mode: str = "line",
        allowed: frozenset[str] | None = HOST_CHARS,
        completions: Iterable[str] = (),
        choices: dict[str, str] | None = None,
        max_len: int = 128,
        width: int = 80,
        cursor: tuple[int, int] | None = None,
    ) -> None:
        self.label = term_safe(label, 100)
        self.mode = mode
        self.allowed = allowed
        self.choices = choices or {}
        self.max_len = max_len
        self.width = max(20, width)
        self.completions = sorted(
            {c for c in list(completions)[:MAX_COMPLETIONS]
             if isinstance(c, str) and c and len(c) <= 255 and (allowed is None or set(c) <= allowed)}
        )
        self.buf = ""
        self.hint = ""
        self.done = False
        self.cancelled = False
        self.result: str | None = None
        self.cursor = cursor

    # ------------------------------------------------------------ Anzeige

    def open(self, *, new_line: bool = True) -> bytes:
        """Neue Zeile (mit Cursor-Abfrage) oder Folgefrage auf derselben Zeile."""
        head = b"\x1b[6n\r\n" if new_line else b""
        return head + self.render()

    def render(self) -> bytes:
        text = f"{self.label}{term_safe(self.buf, self.max_len + 8)}"
        if self.hint:
            text += "  " + term_safe(self.hint, 200)
        text = term_safe(text, self.width - 1)
        return b"\r\x1b[K" + text.encode("utf-8", "replace")

    def close_bytes(self, rows: int) -> bytes:
        """Zeile löschen und Cursor an die Stelle vor dem Prompt setzen."""
        out = b"\r\x1b[K"
        if self.cursor is not None:
            row, col = self.cursor
            if row >= rows:  # der Zeilenumbruch hat den Bildschirm gerollt
                row = max(1, rows - 1)
            out += f"\x1b[{row};{col}H".encode()
        return out

    # ------------------------------------------------------------ Eingabe

    def feed(self, chunk: bytes) -> bytes:
        if self.done:
            return b""
        if chunk == b"\x1b":
            return self._cancel()
        for m in _CPR.finditer(chunk):
            if self.cursor is None:
                self.cursor = (int(m.group(1)), int(m.group(2)))
        chunk = _SEQ.sub(b"", chunk)
        text = chunk.decode("utf-8", "ignore")
        for ch in text:
            if self.done:
                break
            self._key(ch)
        return b"" if self.done else self.render()

    def _cancel(self) -> bytes:
        self.done = True
        self.cancelled = True
        return b""

    def _key(self, ch: str) -> None:
        if ch in ("\x03", "\x07"):
            self._cancel()
            return
        if self.mode == "message":
            self.done = True
            return
        if self.mode == "choice":
            if ch in self.choices:
                self.result = self.choices[ch]
                self.done = True
            return
        if ch in ("\r", "\n"):
            self.result = self.buf
            self.done = True
        elif ch in ("\x7f", "\x08"):
            self.buf = self.buf[:-1]
        elif ch == "\x15":
            self.buf = ""
        elif ch == "\x17":
            self.buf = self.buf.rstrip(" ")
            self.buf = self.buf[: max(self.buf.rfind(" ") + 1, 0)] if " " in self.buf else ""
        elif ch == "\t":
            self._complete()
        elif len(self.buf) < self.max_len and self._ok(ch):
            self.buf += ch
            self.hint = ""

    def _ok(self, ch: str) -> bool:
        if self.allowed is not None:
            return ch in self.allowed
        return ch.isprintable() and term_safe(ch, 0) == ch

    def _complete(self) -> None:
        user, sep, part = self.buf.rpartition("@")
        head = user + sep
        cands = [c for c in self.completions if c.startswith(part)]
        if not cands:
            self.hint = "(keine Treffer)"
            return
        pre = common_prefix(cands)
        if len(head + pre) <= self.max_len:
            self.buf = head + pre
        if len(cands) == 1:
            self.hint = ""
        else:
            self.hint = "[" + " ".join(cands[:12]) + (" ..." if len(cands) > 12 else "") + "]"
