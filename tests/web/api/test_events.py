"""Ereignisquellen für SSE (Vertrag v0.1-Server 3.8): Daemon- und Auswertungsereignisse werden zu
Bus-Ereignissen ohne Zieldaten; Abmelden beendet sie."""

from __future__ import annotations

import asyncio
import json

from ariadne.web.api import attach_sources
from ariadne.web.api.events import JOB_TEXT
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.integration.helpers import Term
from tests.integration.test_daemon_ingest import run
from tests.web.api.helpers import NMAP2, TARGET, FakeBus, build_fixture, make_app, sync


async def _until(pred, timeout: float = 5.0) -> None:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not pred():
        if loop.time() > end:
            raise TimeoutError("Ereignis kam nicht")
        await asyncio.sleep(0.02)


def test_sources_translate_daemon_and_ingest_events(paths, operator):
    async def scenario(d):
        bus = FakeBus()
        _app, ctx = make_app(d, bus)
        detach = attach_sources(ctx)
        fx = await build_fixture(d, paths, inputs=False)
        ev = bus.events
        assert ("project", {"project_id": fx.pid, "change": "opened", "locked": False}) in ev
        assert ("terminal", {"terminal_id": fx.shim.terminal_id, "change": "opened"}) in ev
        changes = [data for e, data in ev if e == "changes"]
        assert changes and all(
            c["project_id"] == fx.pid and isinstance(c["generation"], int) for c in changes
        )
        gens = [c["generation"] for c in changes]
        assert gens == sorted(set(gens))  # jede Generation einmal, aufsteigend
        # Zahl offener Einträge: Widersprüche aus einem zweiten nmap-Lauf
        s3 = await FakeShim(paths.term_sock).connect(proto=2)
        await s3.wait_state(rec="on")
        t3 = Term(s3)
        await t3.command(f"nmap -sV -p21,445 {TARGET}", NMAP2, cwd=str(fx.ws))
        await t3.acked()
        await sync(d)
        await _until(lambda: any(e == "inbox" and x["open"] == 2 for e, x in bus.events))
        inbox = [x for e, x in bus.events if e == "inbox"]
        assert inbox[-1] == {"project_id": fx.pid, "open": 2}
        # Präsentation, Neuauswertung (progress und reset)
        await ctl_ok(paths.ctl_sock, "presentation", on=True)
        assert ("presentation", {"on": True}) in bus.events
        n = len(bus.events)
        await ctl_ok(paths.ctl_sock, "reparse")
        await _until(lambda: any(e == "reset" for e, _ in bus.events[n:]))
        prog = [x for e, x in bus.events[n:] if e == "progress"]
        assert [p["status"] for p in prog] == ["running", "done"]
        assert (
            prog[0]["kind"] == "reparse" and prog[0]["pct"] is None and prog[1]["message"] == JOB_TEXT["done"]
        )
        assert ("reset", {"reason": "reparse"}) in bus.events[n:]
        # lock: Projekt geschlossen, gesperrt
        n = len(bus.events)
        await ctl_ok(paths.ctl_sock, "lock")
        tail = bus.events[n:]
        assert ("project", {"project_id": None, "change": "locked", "locked": True}) in tail
        assert any(e == "project" and x["change"] == "closed" for e, x in tail)
        # nie Zieldaten im Strom
        text = json.dumps(bus.events, ensure_ascii=False)
        assert TARGET not in text and "script" not in text and "nmap" not in text
        # abmelden: keine weiteren Ereignisse
        detach()
        n = len(bus.events)
        await ctl_ok(paths.ctl_sock, "presentation", on=False)
        await s3.close()
        await asyncio.sleep(0.1)
        assert bus.events[n:] == []
        for s in fx.shims:
            await s.close()

    run(paths, operator, scenario)


def test_sources_survive_a_failing_bus(paths, operator):
    class Broken:
        def publish(self, event, data):
            raise RuntimeError("Bus kaputt")

    async def scenario(d):
        _app, ctx = make_app(d, Broken())
        detach = attach_sources(ctx)
        await ctl_ok(paths.ctl_sock, "presentation", on=True)  # Fehler im Bus stört den Daemon nicht
        assert d.presentation is True
        assert (await ctl_ok(paths.ctl_sock, "ping"))["pong"] is True
        detach()
        detach()  # zweimal abmelden ist harmlos

    run(paths, operator, scenario)
