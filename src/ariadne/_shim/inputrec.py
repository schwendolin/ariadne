"""Eingaben ans Kind bündeln (E26, Vertrag v0.1-Bedienung 3.2). Nur Standardbibliothek.

Aufgezeichnet wird genau, was der Shim an das Programm im PTY schreibt (Aktion
``Forward`` des Hotkey-Filters, auch der durchgereichte doppelte Präfix), nie Präfix
und Taste eines Hotkeys und nie Eingaben im Mini-Prompt. Gebündelt wird bis CR, LF,
Ctrl-C oder Ctrl-D (einschliesslich), bis 4 KiB oder 1 s nach dem ersten Byte. Ein
Bracketed Paste (``ESC[200~`` bis ``ESC[201~``, mit den Klammern) ist genau ein
Rahmen mit Paste-Flag (Notbremse: 512 KiB, 2 s ohne Paste-Ende).

Jedes ``read()`` bringt Wanduhr, monotone Uhr und den Ausgabe-Offset mit; ein neuer
Zeitindex-Eintrag entsteht frühestens 1 ms nach dem letzten. Die Bytes gehen nie in
Logs; die Anzeige im Terminal läuft nur über ``term_safe``.

E104: ``feed(..., no_echo=True)`` meldet, dass das Kind beim Tippen im Passwortmodus war
(``ECHO`` aus, ``ICANON`` an). Ein Bündel ist ``no_echo``, sobald eines seiner Bytes so
getippt wurde (lieber zu viel als zu wenig verdecken). ``emit`` bekommt das dann als
Schlüsselwort ``no_echo=True``; ohne Passwortmodus wird es nicht übergeben, ältere
Rückrufe mit sieben Parametern bleiben gültig.
"""

from __future__ import annotations

from collections.abc import Callable

from ariadne._shim import protocol as P

__all__ = ["InputRecorder", "INPUT_MAX", "INPUT_S", "PASTE_MAX", "PASTE_IDLE_S", "TERMINATORS"]

INPUT_MAX = 4096
INPUT_S = 1.0
PASTE_MAX = 512 * 1024
PASTE_IDLE_S = 2.0
TIX_MIN_NS = 1_000_000
TERMINATORS = b"\r\n\x03\x04"
PASTE_START = b"\x1b[200~"
PASTE_END = b"\x1b[201~"

# emit(data, stream_off, out_end, wall_ns, mono_ns, tix, paste[, no_echo=True])
Emit = Callable[..., None]


class InputRecorder:
    def __init__(self, emit: Emit) -> None:
        self._emit = emit
        self.buf = bytearray()
        self._marks: list[tuple[int, int, int, int]] = []  # (rel, wall, mono, out_off)
        self.paste = False
        self.no_echo = False  # E104: ein Byte des laufenden Bündels im Passwortmodus getippt
        self._t0 = 0.0
        self._last = 0.0

    def __bool__(self) -> bool:
        return bool(self.buf)

    def deadline(self) -> float | None:
        if not self.buf:
            return None
        return self._last + PASTE_IDLE_S if self.paste else self._t0 + INPUT_S

    def feed(self, data: bytes, out_off: int, wall: int, mono: int, now: float, *,
             no_echo: bool = False) -> None:
        if not data:
            return
        if not self.buf:
            self._marks = [(0, wall, mono, out_off)]
            self._t0 = now
            self.no_echo = False
        elif mono - self._marks[-1][2] >= TIX_MIN_NS:
            self._marks.append((len(self.buf), wall, mono, out_off))
        self.no_echo = self.no_echo or no_echo
        self.buf += data
        self._last = now
        self._split()

    def expire(self, now: float) -> None:
        d = self.deadline()
        if d is not None and now >= d:
            self.flush()

    def flush(self) -> None:
        """Alles Gepufferte als Rahmen senden (Ablauf, Ende der Aufnahme, vor Anfragen)."""
        if self.buf:
            self._send(len(self.buf), self.paste)
        self.paste = False

    def drop(self) -> None:
        self.buf[:] = bytes(len(self.buf))
        self.buf = bytearray()
        self._marks = []
        self.paste = False
        self.no_echo = False

    # ------------------------------------------------------------------ intern
    def _split(self) -> None:
        while self.buf:
            if self.paste:
                k = self.buf.find(PASTE_END)
                if k >= 0:
                    self._send(k + len(PASTE_END), True)
                    self.paste = False
                    continue
                if len(self.buf) >= PASTE_MAX or len(self._marks) > P.MAX_TIX:
                    self._send(len(self.buf), True)
                return
            i = self.buf.find(PASTE_START)
            ends = [j for j in (self.buf.find(bytes([c])) for c in TERMINATORS) if j >= 0]
            t = min(ends) if ends else -1
            if i >= 0 and (t < 0 or i < t):
                if i > 0:
                    self._send(i, False)
                self.paste = True
                continue
            if t >= 0:
                self._send(t + 1, False)
                continue
            if len(self.buf) >= INPUT_MAX or len(self._marks) > P.MAX_TIX:
                self._send(len(self.buf), False)
            return

    def _send(self, cut: int, paste: bool) -> None:
        marks = self._marks
        base = marks[0]
        tix: list[tuple[int, int]] = []
        last_dt = 0
        out_end = base[3]
        for rel, _wall, mono, off in marks:
            if rel < cut:
                out_end = off
            if 0 < rel < cut:
                last_dt = max(last_dt, min((mono - base[2]) // 1000, 0xFFFFFFFF))
                tix.append((rel, last_dt))
        data = bytes(self.buf[:cut])
        rest_base = base
        rest: list[tuple[int, int, int, int]] = []
        for m in marks:
            if m[0] <= cut:
                rest_base = m
            else:
                rest.append((m[0] - cut, m[1], m[2], m[3]))
        self.buf[:cut] = b""
        self._marks = [(0, rest_base[1], rest_base[2], rest_base[3]), *rest] if self.buf else []
        no_echo = self.no_echo
        if not self.buf:
            self.no_echo = False  # der Rest eines Bündels behält das Flag (lieber zu viel)
        args = (data, base[3], out_end, base[1], base[2], tuple(tix[: P.MAX_TIX]), paste)
        if no_echo:
            self._emit(*args, no_echo=True)
        else:
            self._emit(*args)
