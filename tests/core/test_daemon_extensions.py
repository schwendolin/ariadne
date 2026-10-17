"""Erweiterungspunkte des Daemons für den Web-Server (Vertrag v0.1-Server, Abschnitt 3.3).

Erweiterungen mit Lebenszyklus, zusätzliche ctl-Operationen, Ereignisse ohne Zieldaten und
der Präsentationsmodus. Ein Fehler einer Erweiterung lässt die Aufnahme nie ausfallen.
"""

from __future__ import annotations

from typing import Any

from ariadne.daemon.extensions import default_extensions, web_disabled
from tests.core.fakeshim import FakeShim, ctl, ctl_ok
from tests.core.test_daemon import run


class _Ext:
    def __init__(self, name: str, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.calls: list[str] = []

    async def start(self, daemon: Any) -> None:
        self.calls.append("start")
        if self.fail:
            raise OSError("Port belegt")

    async def stop(self) -> None:
        self.calls.append("stop")


def test_extensions_start_stop_and_failure_is_contained(paths, operator):
    good, bad = _Ext("gut"), _Ext("kaputt", fail=True)

    async def scenario(d) -> None:
        assert good.calls == ["start"] and bad.calls == ["start"]
        res = await ctl_ok(paths.ctl_sock, "ping")  # Daemon läuft trotz Fehler
        assert res["pong"] is True

    run(paths, operator, scenario, extensions=[good, bad])
    assert good.calls == ["start", "stop"] and bad.calls == ["start", "stop"]


def test_extra_ops_and_no_override_of_builtins(paths, operator):
    async def scenario(d) -> None:
        d.add_ops({"ui.test": lambda daemon, args: {"echo": args.get("x")}})
        assert await ctl_ok(paths.ctl_sock, "ui.test", x=3) == {"echo": 3}
        for name in ("status", "ui.test"):
            try:
                d.add_ops({name: lambda daemon, args: {}})
            except ValueError:
                continue
            raise AssertionError(f"{name} liess sich überschreiben")

    run(paths, operator, scenario)


def test_listener_events_carry_no_target_data(paths, operator):
    seen: list[tuple[str, dict[str, Any]]] = []

    async def scenario(d) -> None:
        d.add_listener(lambda kind, data: seen.append((kind, data)))
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"<img src=x onerror=alert(1)>\r\n")
        await s.wait_ack(1)
        await ctl_ok(paths.ctl_sock, "presentation", on=True, source="webui")
        assert (await ctl_ok(paths.ctl_sock, "presentation")) == {"on": True}
        bad = await ctl(paths.ctl_sock, "presentation", on="ja")
        assert bad["error"]["code"] == "invalid"
        await ctl_ok(paths.ctl_sock, "lock")
        await s.bye()
        await s.wait_state(rec="locked")
        await s.close()

    run(paths, operator, scenario)
    kinds = [k for k, _ in seen]
    assert ("project", "opened") in [(k, d.get("change")) for k, d in seen]
    assert ("terminal", "opened") in [(k, d.get("change")) for k, d in seen]
    assert ("presentation", True) in [(k, d.get("on")) for k, d in seen]
    closed = [d for k, d in seen if k == "project" and d.get("change") == "closed"]
    assert closed and closed[0]["reason"] == "lock"
    assert "locked" in kinds and "stopping" in kinds
    assert "onerror" not in repr(seen)


def test_default_extensions_respect_switch(paths):
    assert web_disabled({"ARIADNE_WEB": "0"}) and not web_disabled({})
    assert default_extensions(paths, {"ARIADNE_WEB": "0"}) == []
    exts = default_extensions(paths, {})
    assert [e.name for e in exts] == ["web"]


def test_context_from_web_is_retroactive_and_marked_webui(paths, operator):
    """Web-API (Vertrag 3.2): ``ctx.set`` mit ``source=webui`` und ``from_off`` schreibt den Entscheid
    rückwirkend; für ein beendetes Terminal geht er direkt ins Projekt. ``term.resume`` und die
    Entscheide der Auswertung nehmen ``webui`` als Herkunft an."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"x" * 50)
        await s.wait_ack(1)
        res = await ctl_ok(paths.ctl_sock, "ctx.set", terminal_id=s.terminal_id, host="10.10.10.3",
                           kind="revshell", source="webui", from_off=10)
        assert res["stored"] is True
        bad = await ctl(paths.ctl_sock, "ctx.set", terminal_id=s.terminal_id, host="10.10.10.3",
                        from_off=500)
        assert bad["error"]["code"] == "invalid"
        res = await ctl_ok(paths.ctl_sock, "ctx.set", terminal_id="term-weg-00000001", host="10.10.10.3",
                           source="webui", from_off=7)
        assert res == {"stack": None, "stored": True}
        await ctl_ok(paths.ctl_sock, "term.pause", terminal_id=s.terminal_id, minutes=5, source="webui")
        await ctl_ok(paths.ctl_sock, "term.resume", terminal_id=s.terminal_id, source="webui")
        d.flush()
        recs = list(d.project.journal.iter_events(kinds=["d.ctx.set", "term.pause"]))
        sets = [(r.header["terminal_id"], r.header["from_off"], r.origin)
                for r in recs if r.kind == "d.ctx.set"]
        assert sets == [(s.terminal_id, 10, "webui"), ("term-weg-00000001", 7, "webui")]
        assert [r.header["source"] for r in recs if r.kind == "term.pause"] == ["webui"]
        await s.close()

    run(paths, operator, scenario)
