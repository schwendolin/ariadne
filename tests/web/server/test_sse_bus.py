"""Ereignisbus für SSE (web-api.md 14): Bündelung, Ring, Last-Event-ID, Herzschlag, Grenzen."""

from __future__ import annotations

import asyncio
import json

import pytest

from ariadne.web.sse import EventBus


def _events(chunks: list[bytes]) -> list[tuple[int, str, dict]]:
    out = []
    for c in chunks:
        lines = c.decode().strip().split("\n")
        if lines[0].startswith(":"):
            continue
        eid = int(lines[0].removeprefix("id: "))
        ev = lines[1].removeprefix("event: ")
        assert len(lines) == 3 and lines[2].startswith("data: ")
        out.append((eid, ev, json.loads(lines[2].removeprefix("data: "))))
    return out


def _drain(sub) -> list[bytes]:
    out = []
    while not sub.queue.empty():
        item = sub.queue.get_nowait()
        if item is not None:
            out.append(item)
    return out


def test_unknown_event_and_large_data_are_programming_errors():
    bus = EventBus(id_base=0)
    with pytest.raises(ValueError):
        bus.publish("rec", {})
    with pytest.raises(ValueError):
        bus.publish("changes", {"x": "y" * 5000})


def test_window_bundles_and_keeps_order():
    async def main() -> None:
        bus = EventBus(window_s=0.05, id_base=100)
        sub = bus.subscribe("s1")
        for gen in range(3000):  # ein grosser Import
            bus.publish("changes", {"project_id": "p1", "generation": gen, "entities": {"host": 1}})
        bus.publish("terminal", {"terminal_id": "t1", "change": "state"})
        bus.publish("terminal", {"terminal_id": "t1", "change": "state"})
        bus.publish("project", {"project_id": None, "change": "locked", "locked": True})
        bus.publish("project", {"project_id": None, "change": "unlocked", "locked": False})
        bus.publish("inbox", {"project_id": "p1", "open": 3})
        bus.publish("inbox", {"project_id": "p1", "open": 2})
        await asyncio.sleep(0.15)
        evs = _events(_drain(sub))
        assert [e[1] for e in evs] == ["changes", "terminal", "project", "project", "inbox"]
        assert evs[0][2] == {"project_id": "p1", "generation": 2999, "entities": {"host": 3000}}
        assert evs[4][2]["open"] == 2
        assert [e[0] for e in evs] == [101, 102, 103, 104, 105]
        bus.close_all()

    asyncio.run(main())


def test_last_event_id_replay_reset_and_restart():
    async def main() -> None:
        bus = EventBus(window_s=0.01, id_base=1000, ring_size=5)
        for i in range(8):
            bus.publish("progress", {"job_id": f"j{i}", "kind": "reparse", "status": "running",
                                     "pct": None, "message": "Neuauswertung läuft"})
            bus.flush()
        assert bus.last_id == 1008
        replay = _events(bus.subscribe("s", "1005").initial)
        assert [e[0] for e in replay] == [1006, 1007, 1008]
        assert bus.subscribe("s", "1008").initial == []
        old = _events(bus.subscribe("s", "1001").initial)  # aus dem Ring gefallen
        assert old == [(1008, "reset", {"reason": "buffer"})]
        prev_run = _events(bus.subscribe("s", "999").initial)  # früherer Daemon-Lauf
        assert prev_run[0][1:] == ("reset", {"reason": "restart"})
        assert _events(bus.subscribe("s", "abc").initial)[0][2] == {"reason": "buffer"}
        assert _events(bus.subscribe("s", "99999").initial)[0][2] == {"reason": "restart"}
        bus.close_all()

    asyncio.run(main())


def test_heartbeat_close_and_stream_limit():
    async def main() -> None:
        bus = EventBus(window_s=0.01, heartbeat_s=0.05, id_base=0)
        sub = bus.subscribe("s1")
        it = bus.iterate(sub)
        assert await it.__anext__() == b": ok\n\n"
        assert await asyncio.wait_for(it.__anext__(), 1) == b": hb\n\n"
        bus.publish("presentation", {"on": True})
        assert b"event: presentation" in await asyncio.wait_for(it.__anext__(), 1)
        assert bus.close_session("s1") == 1
        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(it.__anext__(), 1)
        assert bus.streams() == 0
        subs = [bus.subscribe("s2") for _ in range(9)]  # der neunte ersetzt den ältesten
        assert subs[0].closed and not subs[8].closed and bus.streams("s2") == 8
        bus.close_all()
        assert all(s.closed for s in subs) and bus.streams() == 0
        bus.publish("presentation", {"on": False})  # nach dem Schliessen: nichts mehr
        assert bus.subscribe("s3").closed

    asyncio.run(main())


def test_slow_reader_is_closed_not_blocking():
    async def main() -> None:
        bus = EventBus(window_s=0.01, queue_size=3, id_base=0)
        sub = bus.subscribe("s")
        for i in range(5):
            bus.publish("terminal", {"terminal_id": f"t{i}", "change": "opened"})
            bus.flush()
        assert sub.closed and bus.streams() == 0
        bus.close_all()

    asyncio.run(main())
