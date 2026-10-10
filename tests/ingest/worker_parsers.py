"""Parser für die Worker-Tests. Werden im Worker-Prozess über ``modul:Klasse`` geladen."""

from __future__ import annotations

import os
import time
from collections.abc import Iterator
from typing import Any, ClassVar

from ariadne.parsers.api import Mention, Obs, Ref, Span


class _Base:
    id: ClassVar[str] = "w.base"
    version: ClassVar[str] = "1"
    trust: ClassVar[str] = "tool_text"
    auto_eligible: ClassVar[bool] = False

    def match(self, unit: Any) -> int:
        return 5

    def companions(self, argv: Any, cwd: str) -> list[str]:
        return []


class EchoParser(_Base):
    id: ClassVar[str] = "w.echo"

    def match(self, unit: Any) -> int:
        return 20

    def parse(self, unit: Any) -> Iterator[Obs | Mention]:
        for i, line in enumerate(unit.lines):
            yield Mention("text", line.text, Span(i, i, 0, len(line.text)), {"kind": unit.kind})
        yield Obs(Ref.ip("10.10.10.3"), "host.state", "up", Span(0, 0), 0.9)
        yield Obs(Ref.ip("10.10.10.3"), "service.state", Ref("x:y"), Span(0, 0))


class EnvParser(_Base):
    id: ClassVar[str] = "w.env"

    def parse(self, unit: Any) -> Iterator[Mention]:
        import resource

        s = Span(0, 0)
        yield Mention("env", ",".join(sorted(os.environ)), s)
        yield Mention("fds", ",".join(sorted(os.listdir("/proc/self/fd"))), s)
        yield Mention("cwd", os.getcwd(), s)
        for name in ("RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_CORE", "RLIMIT_NOFILE"):
            yield Mention("rlimit", f"{name}={resource.getrlimit(getattr(resource, name))[0]}", s)
        with open("/proc/self/status") as f:
            nnp = [ln.split(":", 1)[1].strip() for ln in f if ln.startswith("NoNewPrivs")]
        yield Mention("nnp", nnp[0] if nnp else "?", s)
        try:
            with open("/tmp/ariadne-worker-test", "w") as f:  # noqa: S108 - muss scheitern
                f.write("x")
            yield Mention("write", "ok", s)
        except OSError as exc:
            yield Mention("write", type(exc).__name__, s)


class BombParser(_Base):
    """Speicherbombe: wächst, bis RLIMIT_AS greift."""

    id: ClassVar[str] = "w.bomb"

    def match(self, unit: Any) -> int:
        return 30

    def parse(self, unit: Any) -> Iterator[Mention]:
        hog = []
        while True:
            hog.append(bytearray(64 << 20))
            hog[-1][::4096] = b"x" * len(hog[-1][::4096])
        yield from ()


class ExitParser(_Base):
    id: ClassVar[str] = "w.exit"

    def parse(self, unit: Any) -> Iterator[Mention]:
        yield Mention("x", "before", Span(0, 0))
        os._exit(7)


class SleepParser(_Base):
    id: ClassVar[str] = "w.sleep"

    def parse(self, unit: Any) -> Iterator[Mention]:
        time.sleep(30)
        yield from ()


class FloodParser(_Base):
    id: ClassVar[str] = "w.flood"

    def parse(self, unit: Any) -> Iterator[Mention]:
        for _ in range(100_000):
            yield Mention("x", "A" * 1000, Span(0, 0))


class BadSpanParser(_Base):
    id: ClassVar[str] = "w.badspan"

    def parse(self, unit: Any) -> Iterator[Mention]:
        yield Mention("x", "ok", Span(0, 0))
        yield Mention("x", "out of range", Span(0, 999))


class MatchCrashParser(_Base):
    id: ClassVar[str] = "w.matchcrash"

    def match(self, unit: Any) -> int:
        raise ValueError("kaputt")

    def parse(self, unit: Any) -> Iterator[Mention]:
        yield from ()


class NeverParser(_Base):
    id: ClassVar[str] = "w.never"

    def match(self, unit: Any) -> int:
        return 0

    def parse(self, unit: Any) -> Iterator[Mention]:
        raise AssertionError("darf nicht laufen")
