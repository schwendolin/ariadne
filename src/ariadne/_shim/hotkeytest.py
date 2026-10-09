"""``ariadne hotkey test``: zeigt im Raw-Mode, welche Bytes pro Taste ankommen.

Nur Standardbibliothek. Jede Zeile zeigt einen ``read()``-Chunk als Hex und in
sichtbarer Form, dazu, wie der Hotkey-Filter des Shims ihn einordnet. ``q``
allein beendet den Test.
"""

from __future__ import annotations

import contextlib
import os
import termios
import time

from ariadne._shim.hotkey import Armed, Cancelled, Forward, InputFilter, Key, describe_prefix, parse_hotkey
from ariadne.termsafe import term_safe

__all__ = ["run_hotkey_test", "describe_chunk"]

_KEYS = {"r": "REC umschalten", "h": "Host setzen", "b": "Stufe schliessen", "k": "Schlüsselschritt",
         "s": "Screenshot", "?": "Hilfe"}


def describe_chunk(chunk: bytes, actions: list) -> str:
    hexs = " ".join(f"{b:02x}" for b in chunk[:48]) + (" ..." if len(chunk) > 48 else "")
    shown = term_safe(chunk.decode("utf-8", "replace"), 60)
    what: list[str] = []
    for a in actions:
        if isinstance(a, Armed):
            what.append("Präfix erkannt, warte auf Taste")
        elif isinstance(a, Key):
            what.append(f"Hotkey {term_safe(a.key, 4)}: {_KEYS.get(a.key, 'unbekannt')}")
        elif isinstance(a, Cancelled):
            what.append(f"abgebrochen ({a.reason})")
        elif isinstance(a, Forward):
            what.append("geht an die Shell" if len(chunk) == 1 else f"Burst, {len(chunk)} Bytes an die Shell")
    return f"{hexs:<40} {shown:<24} {'; '.join(what)}"


def _raw(attrs: list) -> list:
    new = [list(a) if isinstance(a, list) else a for a in attrs]
    new[0] &= ~(termios.BRKINT | termios.ICRNL | termios.INPCK | termios.ISTRIP | termios.IXON)
    new[1] &= ~termios.OPOST
    new[3] &= ~(termios.ECHO | termios.ICANON | termios.IEXTEN | termios.ISIG)
    new[6][termios.VMIN] = 1
    new[6][termios.VTIME] = 0
    return new


def run_hotkey_test(hotkey: str | None = None, fd_in: int = 0, fd_out: int = 1) -> int:
    """Interaktiver Test. Rückgabe 0 bei Ende mit ``q``, 2 ohne Terminal."""

    def say(text: str) -> None:
        os.write(fd_out, text.encode("utf-8", "replace") + b"\r\n")

    if not os.isatty(fd_in):
        os.write(fd_out, b"ariadne hotkey test: kein Terminal.\n")
        return 2
    name, prefix = parse_hotkey(hotkey if hotkey is not None else os.environ.get("ARIADNE_HOTKEY"))
    filt = InputFilter(prefix)
    old = termios.tcgetattr(fd_in)
    say(f"Präfix: {describe_prefix(name)} ({' '.join(f'{b:02x}' for b in prefix)}). "
        "Drücke Tasten, q beendet.")
    say("Ein Hotkey zählt nur, wenn Präfix und Taste je allein ankommen.")
    try:
        termios.tcsetattr(fd_in, termios.TCSANOW, _raw(old))
        while True:
            chunk = os.read(fd_in, 1024)
            if not chunk or chunk == b"q":
                break
            now = time.monotonic()
            acts = filt.feed(chunk, now)
            say(describe_chunk(chunk, acts))
    finally:
        with contextlib.suppress(termios.error, OSError):
            termios.tcsetattr(fd_in, termios.TCSADRAIN, old)
    return 0
