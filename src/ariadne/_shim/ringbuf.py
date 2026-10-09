"""RAM-Ringpuffer für unbestätigte Rahmen (Architektur 3.7). Nur Standardbibliothek.

Die Rahmen liegen in einem anonymen ``mmap`` mit ``MADV_DONTDUMP``, nie auf der
Platte. Einträge haben fortlaufende Sequenznummern; ``release_upto`` gibt nach
einem ACK frei, ein Überlauf verwirft die ältesten Einträge und meldet sie.
"""

from __future__ import annotations

import contextlib
import mmap
from collections.abc import Iterator
from dataclasses import dataclass

__all__ = ["Entry", "FrameRing", "MIN_CAPACITY", "capacity_from_env"]

MIN_CAPACITY = 2 << 20  # 2 MiB, grösser als ein maximaler Rahmen
DEFAULT_MB = 32


def capacity_from_env(value: str | None) -> int:
    """``ARIADNE_SHIM_BUFFER_MB`` lesen (Standard 32, 2 bis 1024 MiB)."""
    try:
        mb = int(value) if value else DEFAULT_MB
    except ValueError:
        mb = DEFAULT_MB
    return max(2, min(mb, 1024)) << 20


@dataclass(frozen=True)
class Entry:
    seq: int
    pos: int
    length: int
    data_len: int = 0  # Nutzbytes bei OUT, sonst 0
    stream_off: int | None = None  # bei OUT der Offset des ersten Bytes


class FrameRing:
    def __init__(self, capacity: int) -> None:
        self.capacity = max(int(capacity), MIN_CAPACITY)
        self._mm = mmap.mmap(-1, self.capacity, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
        if hasattr(mmap, "MADV_DONTDUMP"):
            with contextlib.suppress(OSError):
                self._mm.madvise(mmap.MADV_DONTDUMP)
        self._ents: list[Entry] = []
        self._head = 0
        self.used = 0

    # ------------------------------------------------------------ Abfragen

    def __len__(self) -> int:
        return len(self._ents) - self._head

    def __bool__(self) -> bool:
        return len(self) > 0

    @property
    def first_seq(self) -> int | None:
        return self._ents[self._head].seq if self else None

    @property
    def last_seq(self) -> int | None:
        return self._ents[-1].seq if self else None

    def entry(self, seq: int) -> Entry | None:
        first = self.first_seq
        if first is None or seq < first or seq > self._ents[-1].seq:
            return None
        return self._ents[self._head + seq - first]

    def get(self, seq: int) -> bytes | None:
        e = self.entry(seq)
        return None if e is None else bytes(self._mm[e.pos : e.pos + e.length])

    def entries(self) -> Iterator[Entry]:
        return iter(self._ents[self._head :])

    # ---------------------------------------------------------- Änderungen

    def append(self, seq: int, frame: bytes, data_len: int = 0, stream_off: int | None = None) -> list[Entry]:
        """Hängt einen Rahmen an. Gibt verdrängte Einträge zurück (ältester zuerst).

        Ein Rahmen, der grösser als der ganze Puffer ist, wird selbst als
        verdrängt gemeldet und nicht gespeichert.
        """
        last = self.last_seq
        if last is not None and seq != last + 1:
            raise ValueError("Sequenznummern müssen fortlaufend sein")
        size = len(frame)
        evicted: list[Entry] = []
        if size > self.capacity:
            evicted.extend(self.clear())
            evicted.append(Entry(seq, 0, size, data_len, stream_off))
            return evicted
        while True:
            pos = self._place(size)
            if pos is not None:
                break
            evicted.append(self._pop())
        self._mm[pos : pos + size] = frame
        self._ents.append(Entry(seq, pos, size, data_len, stream_off))
        self.used += size
        return evicted

    def release_upto(self, seq: int) -> int:
        """Gibt alle Einträge bis einschliesslich ``seq`` frei (ACK)."""
        n = 0
        while self and self._ents[self._head].seq <= seq:
            self._pop()
            n += 1
        return n

    def clear(self) -> list[Entry]:
        dropped = list(self.entries())
        self._ents = []
        self._head = 0
        self.used = 0
        return dropped

    def close(self) -> None:
        self.clear()
        with contextlib.suppress(Exception):
            self._mm.close()

    # -------------------------------------------------------------- intern

    def _pop(self) -> Entry:
        e = self._ents[self._head]
        self._head += 1
        self.used -= e.length
        if self._head > 1024 and self._head * 2 > len(self._ents):
            del self._ents[: self._head]
            self._head = 0
        if not self:
            self._ents = []
            self._head = 0
        return e

    def _place(self, size: int) -> int | None:
        if not self:
            return 0
        start = self._ents[self._head].pos
        last = self._ents[-1]
        end = last.pos + last.length
        if last.pos >= start:  # nicht umgebrochen: frei sind [end, cap) und [0, start)
            if self.capacity - end >= size:
                return end
            if start >= size:
                return 0
            return None
        if start - end >= size:  # umgebrochen: frei ist [end, start)
            return end
        return None
