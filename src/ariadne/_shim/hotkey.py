"""Hotkey-Erkennung auf dem Eingabekanal (Architektur 3.4, Entscheid E29).

Nur Standardbibliothek. Auf stdin kommen Tastendrücke, eingefügter Text und
Antworten des Terminals. Ein Hotkey zählt deshalb nur, wenn

* der Präfix allein in einem ``read()`` ankommt und danach die zweite Taste
  ebenfalls allein (innerhalb von 5 s),
* der Eingabestrom davor nicht mitten in einer Escape-Sequenz steht
  (Antworten wie ``ESC P ... ST``, ``ESC ] ... BEL``, ``CSI ... R``),
* kein Bracketed Paste läuft und das letzte Paste-Ende mindestens 50 ms her ist.

Alles andere geht unverändert an das Kind. Zweimal Präfix sendet den Präfix
selbst, Esc bricht ab.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "PREFIXES",
    "parse_hotkey",
    "describe_prefix",
    "Forward",
    "Armed",
    "Key",
    "Cancelled",
    "InputTracker",
    "InputFilter",
    "TIMEOUT_S",
    "PASTE_LOCK_S",
]

PREFIXES: dict[str, bytes] = {
    "f12": b"\x1b[24~",
    "ctrl-space": b"\x00",
    "ctrl-]": b"\x1d",
    "ctrl-_": b"\x1f",
}
_ALIASES = {
    "c-space": "ctrl-space", "ctrl-@": "ctrl-space", "c-]": "ctrl-]", "c-_": "ctrl-_",
}
_LABELS = {"f12": "F12", "ctrl-space": "Ctrl-Space", "ctrl-]": "Ctrl-]", "ctrl-_": "Ctrl-_"}

TIMEOUT_S = 5.0
PASTE_LOCK_S = 0.05
SEQ_TIMEOUT_S = 0.1
PASTE_TIMEOUT_S = 2.0

PASTE_START = b"\x1b[200~"
PASTE_END = b"\x1b[201~"
_STR_STOP = re.compile(rb"[\x07\x1b\x18\x1a]")


def parse_hotkey(name: str | None) -> tuple[str, bytes]:
    """Name aus ``ARIADNE_HOTKEY`` normalisieren. Unbekanntes ergibt ``f12``."""
    key = (name or "").strip().lower().replace("+", "-").replace("_space", "-space")
    key = _ALIASES.get(key, key)
    if key not in PREFIXES:
        key = "f12"
    return key, PREFIXES[key]


def describe_prefix(name: str) -> str:
    return _LABELS.get(name, name)


@dataclass(frozen=True)
class Forward:
    data: bytes


@dataclass(frozen=True)
class Armed:
    pass


@dataclass(frozen=True)
class Key:
    key: str


@dataclass(frozen=True)
class Cancelled:
    reason: str  # esc | abort | timeout | burst


Action = Forward | Armed | Key | Cancelled

_GROUND, _ESC, _ESC_INT, _CSI, _STR, _STR_ESC = range(6)


class InputTracker:
    """Verfolgt Escape-Sequenzen und Bracketed Paste im Eingabestrom."""

    def __init__(self) -> None:
        self.state = _GROUND
        self.since = 0.0
        self.in_paste = False
        self.paste_end = float("-inf")
        self.last_input = float("-inf")
        self._csi = bytearray()
        self._tail = b""

    def clean(self, now: float) -> bool:
        """Darf ein Hotkey zählen? Kein Paste, keine offene Sequenz, keine Sperre."""
        if self.in_paste and now - self.last_input > PASTE_TIMEOUT_S:
            self.in_paste = False
            self._tail = b""
        if self.state != _GROUND and now - self.since > SEQ_TIMEOUT_S:
            self.state = _GROUND
        return self.state == _GROUND and not self.in_paste and now - self.paste_end >= PASTE_LOCK_S

    def update(self, data: bytes, now: float) -> None:
        self.last_input = now
        if data == b"\x1b" and self.state == _GROUND and not self.in_paste:
            return  # einzelnes Esc ist eine Taste
        i, n = 0, len(data)
        while i < n:
            if self.in_paste:
                buf = self._tail + data[i:]
                k = buf.find(PASTE_END)
                if k < 0:
                    self._tail = buf[-(len(PASTE_END) - 1) :]
                    return
                i += k + len(PASTE_END) - len(self._tail)
                self._tail = b""
                self.in_paste = False
                self.paste_end = now
                self.state = _GROUND
                continue
            st = self.state
            if st == _GROUND:
                j = data.find(b"\x1b", i)
                if j < 0:
                    return
                self.state, self.since = _ESC, now
                i = j + 1
                continue
            if st == _STR:
                m = _STR_STOP.search(data, i)
                if m is None:
                    return
                i = m.end()
                self.state = _STR_ESC if data[m.start()] == 0x1B else _GROUND
                continue
            b = data[i]
            i += 1
            if st == _ESC:
                if b == 0x5B:
                    self.state = _CSI
                    self._csi = bytearray()
                elif b in b"]P_^X":
                    self.state = _STR
                elif 0x20 <= b <= 0x2F:
                    self.state = _ESC_INT
                elif b == 0x1B:
                    self.since = now
                elif b < 0x20 and b not in (0x18, 0x1A):
                    pass
                else:
                    self.state = _GROUND
            elif st == _ESC_INT:
                if 0x30 <= b <= 0x7E or b in (0x18, 0x1A):
                    self.state = _GROUND
                elif b == 0x1B:
                    self.state, self.since = _ESC, now
            elif st == _CSI:
                if 0x40 <= b <= 0x7E:
                    if b == 0x7E and bytes(self._csi) == b"200":
                        self.in_paste = True
                        self._tail = b""
                    self.state = _GROUND
                elif 0x20 <= b <= 0x3F:
                    if len(self._csi) < 64:
                        self._csi.append(b)
                elif b in (0x18, 0x1A):
                    self.state = _GROUND
                elif b == 0x1B:
                    self.state, self.since = _ESC, now
            elif st == _STR_ESC:
                if b == 0x5C:
                    self.state = _GROUND
                else:
                    self.state, self.since = _ESC, now
                    i -= 1  # Byte im ESC-Zustand neu lesen


class InputFilter:
    """Entscheidet pro ``read()``-Chunk: durchreichen, Präfix, Taste oder Abbruch."""

    def __init__(self, prefix: bytes) -> None:
        self.prefix = prefix
        self.tracker = InputTracker()
        self.armed_at: float | None = None

    @property
    def armed(self) -> bool:
        return self.armed_at is not None

    def deadline(self) -> float | None:
        return None if self.armed_at is None else self.armed_at + TIMEOUT_S

    def expire(self, now: float) -> list[Action]:
        if self.armed_at is not None and now >= self.armed_at + TIMEOUT_S:
            self.armed_at = None
            return [Cancelled("timeout")]
        return []

    def observe(self, chunk: bytes, now: float) -> None:
        """Eingabe, die anderswo verbraucht wird (Mini-Prompt), nur mitverfolgen."""
        self.tracker.update(chunk, now)

    def feed(self, chunk: bytes, now: float) -> list[Action]:
        acts: list[Action] = self.expire(now)
        clean = self.tracker.clean(now)
        if self.armed_at is not None:
            self.armed_at = None
            if clean:
                if chunk == self.prefix:
                    acts.append(Forward(chunk))
                    self.tracker.update(chunk, now)
                    return acts
                if chunk == b"\x1b":
                    acts.append(Cancelled("esc"))
                    return acts
                if chunk in (b"\x03", b"\x07"):
                    acts.append(Cancelled("abort"))
                    return acts
                if len(chunk) == 1 and 0x20 < chunk[0] < 0x7F:
                    acts.append(Key(chr(chunk[0])))
                    return acts
            acts.append(Cancelled("burst"))
        elif clean and chunk == self.prefix:
            self.armed_at = now
            acts.append(Armed())
            return acts
        self.tracker.update(chunk, now)
        acts.append(Forward(chunk))
        return acts
