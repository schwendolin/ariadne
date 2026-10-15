"""Daemon-Integration mit Fake-Shim über echte Unix-Sockets im tmp-Runtime-Ordner.

Grundfluss, Kontext, Hotkeys, Fehler. Daueraufnahme, Pause, Vorlauf, Wechsel und Zeit
stehen in ``test_daemon_capture.py``.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from ariadne.daemon.core import Daemon
from tests.core.conftest import OWN_SECRET
from tests.core.fakeshim import FakeShim, ctl, ctl_ok


async def _fake_clock() -> dict[str, Any]:
    return {"detail": "test"}


def run(paths, operator, scenario: Callable[[Daemon], Awaitable[None]], **kw: Any) -> Daemon:
    kw.setdefault("local_addrs", lambda: None)  # deterministisch: kein Blick nach /proc

    async def main() -> Daemon:
        d = Daemon(paths, check_peer_comm=False, operator=operator, batch_interval=0.02,
                   clock_check=_fake_clock, **kw)
        await d.start()
        try:
            await scenario(d)
        finally:
            await d.stop()
        return d

    return asyncio.run(main())


def stream_of(journal, terminal_id: str) -> bytes:
    outs = sorted(journal.iter_events(kinds=["term.out"], terminal_id=terminal_id),
                  key=lambda r: r.stream_off)
    data = b""
    for r in outs:
        assert r.stream_off == len(data), "Strom hat Lücken oder Überlappungen"
        data += r.body or b""
    return data


def kinds(journal) -> list[str]:
    return [r.kind for r in journal.iter_events()]


# --------------------------------------------------------------------------- #


def test_record_flow_ack_duplicates_ctx_and_no_redaction(paths, operator):
    seen: dict[str, Any] = {"commits": [], "marks": []}

    async def scenario(d: Daemon) -> None:
        d.add_commit_hook(lambda recs: seen["commits"].append([r.kind for r in recs]))
        d.add_mark_hook(lambda rec, ctx: seen["marks"].append((rec.header["mark"], ctx.local)))
        d.add_commit_hook(lambda recs: 1 / 0)  # fehlerhafter Hook darf nichts stoppen

        res = await ctl_ok(paths.ctl_sock, "project.new", slug="lame", targets=["10.10.10.3"])
        assert res["opened"]
        shim = await FakeShim(paths.term_sock).connect()
        st = await shim.wait_state(rec="on")  # Daueraufnahme: kein REC-Schalter (E22)
        assert st["project"] == "lame" and st["bound_project_id"] == st["project_id"]

        await shim.out(1, 0, b"$ sudo -v\r\n[sudo] pass")
        await shim.out(2, 22, b"word: " + OWN_SECRET[:7].encode())
        await shim.out(3, 35, OWN_SECRET[7:].encode() + b"\r\n")
        await shim.out(3, 35, OWN_SECRET[7:].encode() + b"\r\n")  # Wiederholung
        await shim.event(4, "term.mark", stream_off=46, mark="A", counter=1, fg_shell=True)
        await shim.wait_ack(4)

        # Hotkey: Kontext setzen
        await shim.event(5, "req.ctx.set", host="10.10.10.3", user="root")
        await shim._wait(lambda: shim.state["stack"][-1].get("host") == "ip:default/10.10.10.3", 3)
        await shim.wait_ack(5)
        await shim.event(6, "term.mark", stream_off=46, mark="C", counter=2, fg_shell=True,
                         cmd_typed=f"echo {OWN_SECRET}", cwd="/root")
        await shim.wait_ack(6)

        j = d.project.journal
        data = stream_of(j, shim.terminal_id)
        # E72: das Journal speichert alles (verschlüsselt), geschwärzt wird erst am Ausgang
        assert data == b"$ sudo -v\r\n[sudo] password: " + OWN_SECRET.encode() + b"\r\n"
        assert all(not r.header.get("redactions") for r in j.iter_events(kinds=["term.out"]))
        red, labels = d.redactor.redact_for_exit(data)
        assert OWN_SECRET.encode() not in red and labels == ["sudo"] and len(red) == len(data)

        ks = kinds(j)
        assert ks[:2] == ["system.project_created", "d.scope.update"]
        for k in ("term.open", "term.bind", "term.ctx_snapshot", "term.mark", "d.ctx.set"):
            assert k in ks, k
        assert "rec.set" not in ks
        assert ks.index("term.open") < ks.index("term.out")
        dctx = next(j.iter_events(kinds=["d.ctx.set"]))
        assert dctx.origin == "shim" and dctx.header["host"] == "ip:default/10.10.10.3"
        mark_c = [r for r in j.iter_events(kinds=["term.mark"]) if r.header["mark"] == "C"][0]
        assert mark_c.header["cmd_typed"] == f"echo {OWN_SECRET}"
        assert j.verify().ok
        assert seen["marks"] and seen["marks"][0] == ("A", True)
        assert any("term.out" in c for c in seen["commits"])
        await shim.close()

    run(paths, operator, scenario)


def test_pause_terminal_sensitive_output(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="p", targets=["10.0.0.5"])
        shim = await FakeShim(paths.term_sock).connect()
        await shim.wait_state(rec="on")
        await shim.out(1, 0, b"$ ariadne init\r\n")
        await shim.wait_ack(1)
        res = await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=shim.terminal_id)
        assert res["paused"]
        await shim.out(2, 16, b"Recovery-Code: ABCD-EFGH\r\n")
        await shim.event(3, "term.mark", stream_off=42, mark="D", counter=5, fg_shell=True, exit=0)
        await shim.out(4, 42, b"$ ")
        await shim.wait_ack(4)
        d.flush()
        j = d.project.journal
        data = stream_of_with_gaps(j, shim.terminal_id)
        assert b"Recovery" not in data and data == b"$ ariadne init\r\n$ "
        gaps = [{k: r.header[k] for k in ("stream_off", "reason", "bytes_lost")}
                for r in j.iter_events(kinds=["term.gap"])]
        assert gaps == [{"stream_off": 16, "reason": "sensitive_output", "bytes_lost": 26}]
        await shim.close()

    run(paths, operator, scenario)


def test_pause_terminal_seconds_outlast_the_secret_prompt(paths, operator):
    """Die CLI meldet ihr Terminal länger an als ``pause_timeout`` (Abfrage der Passphrase)."""
    async def scenario(d: Daemon) -> None:
        res = await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id="term-cli-000002", seconds=660)
        assert res["pending"]
        shim = FakeShim(paths.term_sock, "term-cli-000002")
        await shim.connect(proto=2)
        await shim.wait_state(rec="preroll")
        left = d.terminals["term-cli-000002"].pause.deadline - time.monotonic()
        assert 600 < left <= 660
        await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id="term-cli-000002", seconds=5)
        assert d.terminals["term-cli-000002"].pause.deadline - time.monotonic() > 600  # nie verkürzt
        bad = await ctl(paths.ctl_sock, "pause_terminal", terminal_id="term-cli-000002", seconds=99999)
        assert not bad["ok"]
        await shim.close()

    run(paths, operator, scenario)


def stream_of_with_gaps(journal, terminal_id: str) -> bytes:
    return b"".join(r.body or b"" for r in journal.iter_events(kinds=["term.out"], terminal_id=terminal_id))


def test_ctl_errors_and_status(paths, operator):
    async def scenario(d: Daemon) -> None:
        resp = await ctl(paths.ctl_sock, "nope")
        assert not resp["ok"] and resp["error"]["code"] == "unknown_op"
        resp = await ctl(paths.ctl_sock, "project.new", slug="cust", targets=["8.8.8.8"])
        assert resp["error"]["code"] == "guardrail" and resp["error"]["outside"] == ["8.8.8.8"]
        resp = await ctl(paths.ctl_sock, "project.new", slug="cust", targets=["x.example"],
                         profile="customer")
        assert resp["error"]["code"] == "project" and "v0.3" in resp["error"]["message"]
        resp = await ctl(paths.ctl_sock, "verify")
        assert resp["error"]["code"] == "no_project"
        res = await ctl_ok(paths.ctl_sock, "project.new", slug="ok", targets=["8.8.8.8"], not_customer=True)
        assert res["opened"]
        assert "d.lab.not_customer" in kinds(d.project.journal)
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["operator"]["unlocked"] and st["project"]["slug"] == "ok" and st["rec"] is True
        assert st["waiting"] == 0 and st["active"] == {"slug": "ok", "stopped": False}
        assert st["locked"] is False and st["idle"]["end_after_s"] == 12 * 3600
        resp = await ctl(paths.ctl_sock, "rec.off")
        assert resp["error"]["code"] == "removed" and "ariadne pause" in resp["error"]["message"]
        assert (await ctl(paths.ctl_sock, "rec.toggle"))["error"]["code"] == "removed"
        rs = await ctl_ok(paths.ctl_sock, "rec.on")  # Kompatibilität: schaltet nichts
        assert rs["state"] == "on" and rs["rec"] is True
        labels = await ctl_ok(paths.ctl_sock, "secrets.add", label="api", value="sk-test-1234567")
        assert labels["labels"] == ["sudo", "api"]
        listed = await ctl_ok(paths.ctl_sock, "secrets.list")
        assert "sk-test" not in str(listed)
        v = await ctl_ok(paths.ctl_sock, "verify")
        assert v["ok"] and v["events"] >= 3
        lst = await ctl_ok(paths.ctl_sock, "project.list")
        assert [p["slug"] for p in lst["projects"]] == ["ok"] and lst["projects"][0]["active"]

    run(paths, operator, scenario)


def test_redact_via_ctl(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="r", targets=["10.1.1.1"])
        shim = await FakeShim(paths.term_sock).connect()
        await shim.wait_state(rec="on")
        await shim.out(1, 0, b"mein privates passwort: hunter22\r\n")
        await shim.event(2, "term.mark", stream_off=34, mark="A", counter=1, fg_shell=True)
        await shim.wait_ack(2)
        out = [r for r in d.project.journal.iter_events(kinds=["term.out"])
               if r.stream_off <= 24 and r.stream_off + r.header["length"] >= 32][0]
        res = await ctl_ok(paths.ctl_sock, "redact", seq=out.seq, label="privat", reason="eigenes Passwort",
                           range=[24, 32])
        red = d.project.journal.get(res["redaction_seq"])
        full = b"mein privates passwort: ********\r\n"
        assert red.kind == "system.redaction"
        assert red.body == full[out.stream_off:out.stream_off + out.header["length"]]
        assert d.project.journal.get(out.seq).body is None
        assert (await ctl_ok(paths.ctl_sock, "verify"))["ok"]
        await shim.close()

    run(paths, operator, scenario)


def test_peer_comm_check_rejects_non_shim(paths, operator):
    async def scenario(d: Daemon) -> None:
        shim = await FakeShim(paths.term_sock).connect()
        with pytest.raises(TimeoutError):
            await shim.wait_state(timeout=0.5)
        await shim.close()

    async def main() -> None:
        d = Daemon(paths, check_peer_comm=True, operator=operator, clock_check=_fake_clock)
        await d.start()
        try:
            await scenario(d)
        finally:
            await d.stop()

    asyncio.run(main())


def test_single_instance(paths, operator):
    from ariadne.daemon.hardening import AlreadyRunning

    async def main() -> None:
        d1 = Daemon(paths, check_peer_comm=False, clock_check=_fake_clock)
        await d1.start()
        try:
            d2 = Daemon(paths, check_peer_comm=False, clock_check=_fake_clock)
            with pytest.raises(AlreadyRunning):
                await d2.start()
        finally:
            await d1.stop()

    asyncio.run(main())


def test_ctx_requests_keystep_shot_and_ctl_ctx(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="ctx", targets=["10.10.10.0/24"])
        shim = await FakeShim(paths.term_sock).connect()
        await shim.wait_state(rec="on")
        tid = shim.terminal_id
        # automatischer Session-Start über den C-Marker
        await shim.event(1, "term.mark", stream_off=0, mark="C", counter=1, fg_shell=True,
                         cmd_typed="ssh root@10.10.10.5")
        await shim._wait(lambda: len(shim.state.get("stack", [])) == 2, 3)
        assert shim.state["stack"][-1]["kind"] == "ssh"
        await shim.event(2, "req.ctx.push", host="web01", user="www-data", stage_kind="revshell")
        await shim._wait(lambda: len(shim.state["stack"]) == 3, 3)
        assert shim.state["stack"][-1]["host"] == "name:web01"
        await shim.event(3, "req.ctx.pop")
        await shim._wait(lambda: len(shim.state["stack"]) == 2, 3)
        await shim.event(4, "req.keystep", step="foothold", note="ssh mit Standardpasswort")
        await shim._wait(lambda: shim.state.get("title_extra") == "Schlüsselschritt: foothold", 3)
        await shim.event(5, "req.shot")
        await shim._wait(lambda: "späteren Version" in (shim.state.get("title_extra") or ""), 3)
        await shim.event(6, "req.ctx.set", host="evil host;rm -rf /")
        await shim._wait(lambda: shim.state.get("title_extra") == "Eingabe ungültig", 3)
        await shim.wait_ack(6)

        res = await ctl_ok(paths.ctl_sock, "ctx.set", terminal_id=tid, host="10.10.10.5", user="root")
        assert res["stored"] and res["stack"][-1]["host"] == "ip:default/10.10.10.5"
        shown = await ctl_ok(paths.ctl_sock, "ctx.show", terminal_id=tid)
        assert shown["label"] == "10.10.10.5 root"
        resp = await ctl(paths.ctl_sock, "ctx.show", terminal_id="gibt-es-nicht")
        assert resp["error"]["code"] == "unknown_terminal"
        terms = await ctl_ok(paths.ctl_sock, "terminals")
        assert terms["terminals"][0]["terminal_id"] == tid and terms["terminals"][0]["recording"]

        await shim.event(7, "term.mark", stream_off=0, mark="D", counter=2, fg_shell=True, exit=0)
        await shim._wait(lambda: len(shim.state["stack"]) == 1, 3)
        await shim.wait_ack(7)
        await asyncio.sleep(0.05)
        j = d.project.journal
        ks = kinds(j)
        for k in ("d.ctx.push", "d.ctx.pop", "d.keystep.mark", "d.ctx.set"):
            assert k in ks, k
        key = next(j.iter_events(kinds=["d.keystep.mark"]))
        # oberste Stufe ist die ssh-Sitzung mit noch unbekanntem Host: kein Host im Entscheid
        assert key.header["step"] == "foothold" and "host" not in key.header
        assert key.header["note"] == "ssh mit Standardpasswort" and key.origin == "shim"
        sets = [r for r in j.iter_events(kinds=["d.ctx.set"])]
        assert [r.origin for r in sets] == ["cli"]
        await shim.close()

    run(paths, operator, scenario)


def test_submit_and_flush_for_other_sources(paths, operator):
    from ariadne.daemon.core import OpError
    from ariadne.store.api import AppendItem

    async def scenario(d: Daemon) -> None:
        with pytest.raises(OpError):
            d.submit(AppendItem("d.note.set", {"subject": "ip:default/10.0.0.1", "text": "x"}))
        await ctl_ok(paths.ctl_sock, "project.new", slug="src", targets=["10.0.0.0/24"])
        got: list[str] = []
        d.add_commit_hook(lambda recs: got.extend(r.kind for r in recs))
        with pytest.raises(ValueError):
            d.submit(AppendItem("d.note.set", {"subject": "x"}))
        d.submit(AppendItem("d.note.set", {"subject": "ip:default/10.0.0.1", "text": "Notiz"},
                            origin="webui"))
        recs = [r for r in d.flush() if r.kind == "d.note.set"]  # clock.check kann mitkommen
        assert len(recs) == 1 and recs[0].origin == "webui"
        assert "d.note.set" in got

    run(paths, operator, scenario)


def _stage(kind: str, opened_at: int = 0, **kw: Any) -> dict[str, Any]:
    return {"kind": kind, "opened_at": opened_at, **kw}


def test_shim_stack_is_authoritative_while_not_recording(paths, operator):
    """Befund: Daemon kennt Marker nur bei Aufnahme; sein Stapel darf beim Start der Aufnahme
    und nach einem Neustart nicht den des Shims ersetzen."""
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="stk", targets=["10.10.10.0/24"])
        stk = d.project.info
        await ctl_ok(paths.ctl_sock, "project.close")  # kein Projekt: Vorlauf
        # Neues Terminal (z. B. nach Daemon-Neustart mitten in einer ssh-Sitzung)
        shim = await FakeShim(paths.term_sock).connect(
            proto=2, stack=[_stage("local", host="local"),
                            _stage("ssh", 40, candidate="10.10.10.5", user="root")])
        st = await shim.wait_state(rec="preroll")
        assert [s["kind"] for s in st["stack"]] == ["local", "ssh"]
        # Pause: nc -lvnp im Shim erkannt, der Daemon bekommt den Stapel per req.ctx.sync
        await shim.event(1, "req.pause", minutes=5)
        await shim.wait_state(rec="paused")
        await shim.event(2, "req.ctx.sync", stack=[_stage("local", host="local"),
                                                   _stage("ssh", 40, candidate="10.10.10.5", user="root"),
                                                   _stage("revshell", 900)])
        await shim.wait_ack(2)
        # Entscheid ohne Aufnahme: wirkt auf den Stapel, wird aber nicht am alten Offset gespeichert
        await shim.event(3, "req.ctx.set", host="10.10.10.7", stream_off=950)
        st = await shim._wait(lambda: shim.state if shim.state.get("ctx_version") == 1 else None, 3)
        assert st["stack"][-1]["host"] == "ip:default/10.10.10.7"
        await shim.event(4, "req.keystep", step="foothold")
        await shim.wait_ack(4)
        await ctl_ok(paths.ctl_sock, "project.open", slug=stk.slug)
        await shim.event(5, "req.pause", minutes=0)
        await shim.wait_state(rec="on")
        await shim.event(6, "term.gap", stream_off=0, reason="pause", bytes_lost=1000)
        await shim.outx(7, 1000, b"uid=0(root)\r\n")
        await shim.wait_ack(7)
        d.flush()
        j = d.project.journal
        assert list(j.iter_events(kinds=["d.ctx.set"])) == []
        snap = next(j.iter_events(kinds=["term.ctx_snapshot"]))
        assert [s["kind"] for s in snap.header["stack"]] == ["local", "ssh", "revshell"]
        assert snap.header["stack"][-1]["host"] == "ip:default/10.10.10.7"
        assert list(j.iter_events(kinds=["d.keystep.mark"])) == []  # ohne Projekt nicht gespeichert
        # neues Terminal im Projekt: beginnt am aktuellen Offset, ohne Lücke
        assert [g.header for g in j.iter_events(kinds=["term.gap"])] == []
        opened = next(j.iter_events(kinds=["term.open"]))
        assert opened.stream_off == 1000
        await shim.close()

    run(paths, operator, scenario)


def test_binding_survives_daemon_restart_via_hello(paths, operator):
    async def scenario(d: Daemon) -> None:
        a = await ctl_ok(paths.ctl_sock, "project.new", slug="alpha", targets=["10.10.10.0/24"])
        await ctl_ok(paths.ctl_sock, "project.new", slug="beta", targets=["10.10.20.0/24"])
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["project"]["slug"] == "beta" and a["opened"]
        alpha_id = next(p["id"] for p in (await ctl_ok(paths.ctl_sock, "project.list"))["projects"]
                        if p["slug"] == "alpha")
        shim = await FakeShim(paths.term_sock).connect(bound_project_id=alpha_id, bound_slug="alpha")
        st = await shim.wait_state(project="beta")
        assert st["rec"] == "off" and st["bound_project_id"] == alpha_id  # v1: held -> off
        assert "alpha" in (st["title_extra"] or "")
        await shim.out(1, 0, b"evil-winrm Sitzung zu alpha\r\n")
        await shim.wait_ack(1)
        d.flush()
        assert list(d.project.journal.iter_events(kinds=["term.out"])) == []
        assert d.state_of(d.terminals[shim.terminal_id]) == "held"
        await shim.close()

    run(paths, operator, scenario)


def test_bye_writes_term_close(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="bye", targets=["10.10.10.0/24"])
        shim = await FakeShim(paths.term_sock).connect(proto=2)
        await shim.wait_state(rec="on")
        await shim.outx(1, 0, b"eins\r\n")
        await shim.wait_ack(1)
        await ctl_ok(paths.ctl_sock, "term.pause", terminal_id=shim.terminal_id)
        await shim.wait_state(rec="paused")
        await shim.bye(0)
        await shim._wait(lambda: shim.closed, 3)
        closes = [r.header for r in d.project.journal.iter_events(kinds=["term.close"])]
        assert len(closes) == 1 and closes[0]["stream_off"] == 6
        assert closes[0]["t_shim_ns"] > 0  # Shim-Zeit am Offset bekannt (Zeitindex der Rahmen)
        await shim.close()

    run(paths, operator, scenario)


def test_shim_overflow_gap_reason_from_hello_and_no_duplicate(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="gap", targets=["10.10.10.0/24"])
        shim = await FakeShim(paths.term_sock).connect(gap_hint="buffer_overflow")
        await shim.wait_state(rec="on")
        await shim.out(1, 0, b"x" * 10)
        await shim.out(2, 100, b"y\r\n")  # Rahmen dazwischen im Shim-Ring verdrängt
        await shim.event(3, "term.gap", stream_off=10, reason="buffer_overflow", bytes_lost=90)
        await shim.wait_ack(3)
        d.flush()
        gaps = [r.header for r in d.project.journal.iter_events(kinds=["term.gap"])]
        assert len(gaps) == 1
        assert {k: gaps[0][k] for k in ("stream_off", "reason", "bytes_lost")} == {
            "stream_off": 10, "reason": "buffer_overflow", "bytes_lost": 90}
        await shim.close()

    run(paths, operator, scenario)
