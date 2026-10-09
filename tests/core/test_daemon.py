"""Daemon-Integration mit Fake-Shim über echte Unix-Sockets im tmp-Runtime-Ordner."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from ariadne.daemon.core import Daemon
from tests.core.conftest import OWN_SECRET
from tests.core.fakeshim import FakeShim, ctl, ctl_ok


async def _fake_clock() -> dict[str, Any]:
    return {"detail": "test"}


def run(paths, operator, scenario: Callable[[Daemon], Awaitable[None]], **kw: Any) -> Daemon:
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


def test_record_flow_redaction_ack_duplicates_ctx(paths, operator):
    seen: dict[str, Any] = {"commits": [], "marks": []}

    async def scenario(d: Daemon) -> None:
        d.add_commit_hook(lambda recs: seen["commits"].append([r.kind for r in recs]))
        d.add_mark_hook(lambda rec, ctx: seen["marks"].append((rec.header["mark"], ctx.local)))
        d.add_commit_hook(lambda recs: 1 / 0)  # fehlerhafter Hook darf nichts stoppen

        res = await ctl_ok(paths.ctl_sock, "project.new", slug="lame", targets=["10.10.10.3"])
        assert res["opened"]
        shim = await FakeShim(paths.term_sock).connect()
        st = await shim.wait_state(rec="off")
        assert st["project"] == "lame" and st["bound_project_id"] is None

        await ctl_ok(paths.ctl_sock, "rec.on")
        st = await shim.wait_state(rec="on")
        assert st["bound_project_id"] == st["project_id"]

        await shim.out(1, 0, b"$ sudo -v\r\n[sudo] pass")
        await shim.out(2, 22, b"word: " + OWN_SECRET[:7].encode())
        await shim.out(3, 35, OWN_SECRET[7:].encode() + b"\r\n")
        await shim.out(3, 35, OWN_SECRET[7:].encode() + b"\r\n")  # Wiederholung
        await shim.event(4, "term.mark", stream_off=46, mark="A", counter=1, fg_shell=True)
        await shim.wait_ack(4)

        # Hotkey: Kontext setzen
        await shim.event(5, "req.ctx.set", host="10.10.10.3", user="root")
        st = await shim.wait_state(timeout=3)
        await shim._wait(lambda: shim.state["stack"][-1].get("host") == "ip:default/10.10.10.3", 3)
        await shim.wait_ack(5)
        await shim.event(6, "term.mark", stream_off=46, mark="C", counter=2, fg_shell=True,
                         cmd_typed=f"echo {OWN_SECRET}", cwd="/root")
        await shim.wait_ack(6)

        j = d.project.journal
        data = stream_of(j, shim.terminal_id)
        assert OWN_SECRET.encode() not in data
        assert data == b"$ sudo -v\r\n[sudo] password: " + b"*" * len(OWN_SECRET) + b"\r\n"
        outs = list(j.iter_events(kinds=["term.out"]))
        reds = [r for o in outs for r in o.header.get("redactions", [])]
        assert reds and reds[0]["label"] == "sudo"
        assert reds[0]["end"] - reds[0]["start"] == len(OWN_SECRET)

        ks = kinds(j)
        assert ks[:2] == ["system.project_created", "d.scope.update"]
        for k in ("rec.set", "term.open", "term.bind", "term.ctx_snapshot", "term.mark", "d.ctx.set"):
            assert k in ks, k
        assert ks.index("term.open") < ks.index("term.out")
        dctx = next(j.iter_events(kinds=["d.ctx.set"]))
        assert dctx.origin == "shim" and dctx.header["host"] == "ip:default/10.10.10.3"
        mark_c = [r for r in j.iter_events(kinds=["term.mark"]) if r.header["mark"] == "C"][0]
        assert OWN_SECRET not in mark_c.header["cmd_typed"]
        assert j.verify().ok
        assert seen["marks"] and seen["marks"][0] == ("A", True)
        assert any("term.out" in c for c in seen["commits"])
        await shim.close()

    run(paths, operator, scenario)


def test_project_switch_writes_gap_and_pauses(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="alpha", targets=["10.10.10.0/24"])
        await ctl_ok(paths.ctl_sock, "rec.on")
        shim = await FakeShim(paths.term_sock).connect()
        st = await shim.wait_state(rec="on")
        alpha_id = st["project_id"]
        await shim.out(1, 0, b"in alpha\r\n")
        await shim.wait_ack(1)
        alpha_journal = d.project.journal

        await ctl_ok(paths.ctl_sock, "project.new", slug="beta", targets=["beta.htb"])
        st = await shim.wait_state(project="beta")
        assert st["rec"] == "off" and st["bound_project_id"] == alpha_id
        assert "pausiert" in (st["title_extra"] or "")
        # Daten nach dem Wechsel landen nicht in beta.
        await shim.out(2, 10, b"nach wechsel\r\n")
        await shim.wait_ack(2)
        assert list(d.project.journal.iter_events(kinds=["term.out"])) == []

        # alpha prüfen (wieder öffnen)
        await ctl_ok(paths.ctl_sock, "project.open", slug="alpha")
        gaps = [r.header for r in d.project.journal.iter_events(kinds=["term.gap"])]
        assert {"terminal_id": shim.terminal_id, "stream_off": 10, "reason": "project_switch",
                "bytes_lost": 0} in gaps
        assert alpha_journal is not d.project.journal
        await shim.close()

    run(paths, operator, scenario, idle_flush=0.05)


def test_locked_project_means_waiting_and_buffer(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="lab1", targets=["192.168.56.0/24"])
        await ctl_ok(paths.ctl_sock, "rec.on")
        shim = await FakeShim(paths.term_sock).connect()
        await shim.wait_state(rec="on")
        await shim.out(1, 0, b"vorher\r\n")
        await shim.wait_ack(1)

        backup = dataclasses.replace(operator, _secrets=list(operator.own_secrets))
        await ctl_ok(paths.ctl_sock, "lock")
        await shim.wait_state(rec="waiting")
        await shim.out(2, 8, b"im Sperrzustand\r\n")
        await asyncio.sleep(0.2)
        assert shim.acked == 1  # nichts bestätigt, solange gesperrt

        # Wieder entsperren (ohne scrypt: Operator direkt setzen) und öffnen
        d.operator = backup
        await ctl_ok(paths.ctl_sock, "project.open", slug="lab1")
        await shim.wait_state(rec="on")
        await shim.wait_ack(2)
        data = stream_of(d.project.journal, shim.terminal_id)
        assert data == b"vorher\r\nim Sperrzustand\r\n"
        await shim.close()

    run(paths, operator, scenario, idle_flush=0.05)


def test_gap_on_rec_off_and_hotkey_rec(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="g", targets=["10.129.1.1"])
        shim = await FakeShim(paths.term_sock).connect()
        await shim.wait_state(rec="off")
        await shim.event(1, "req.rec", on=None)  # Hotkey: umschalten
        await shim.wait_state(rec="on")
        await shim.out(2, 0, b"eins\r\n")
        await shim.wait_ack(2)
        await shim.event(3, "req.rec", on=False)
        await shim.wait_state(rec="off")
        await shim.out(4, 6, b"nicht aufgenommen\r\n")
        await shim.wait_ack(4)
        await ctl_ok(paths.ctl_sock, "rec.on")
        await shim.wait_state(rec="on")
        await shim.out(5, 25, b"zwei\r\n")
        await shim.wait_ack(5)
        j = d.project.journal
        recs = [r.header for r in j.iter_events(kinds=["rec.set"])]
        assert recs[0] == {"on": True, "source": "hotkey", "terminal_id": shim.terminal_id}
        assert recs[1]["on"] is False
        gaps = [r.header for r in j.iter_events(kinds=["term.gap"])]
        assert {"terminal_id": shim.terminal_id, "stream_off": 6, "reason": "rec_off",
                "bytes_lost": 19} in gaps
        assert any(r.header["reason"] == "rec_off" for r in j.iter_events(kinds=["system.checkpoint"]))
        assert "clock.check" in kinds(j)
        await shim.close()

    run(paths, operator, scenario, idle_flush=0.05)


def test_pause_terminal_sensitive_output(paths, operator):
    async def scenario(d: Daemon) -> None:
        await ctl_ok(paths.ctl_sock, "project.new", slug="p", targets=["10.0.0.5"])
        await ctl_ok(paths.ctl_sock, "rec.on")
        shim = await FakeShim(paths.term_sock).connect()
        await shim.wait_state(rec="on")
        await shim.out(1, 0, b"$ ariadne init\r\n")
        await shim.wait_ack(1)
        res = await ctl_ok(paths.ctl_sock, "pause_terminal", terminal_id=shim.terminal_id)
        assert res["paused"]
        await shim.out(2, 16, b"Recovery-Code: ABCD-EFGH\r\n")
        await shim.event(3, "term.mark", stream_off=42, mark="D", counter=5, fg_shell=True, exit=0)
        await shim.out(4, 42, b"$ ")
        await shim.wait_ack(3)
        await asyncio.sleep(0.05)
        await ctl_ok(paths.ctl_sock, "rec.off")
        j = d.project.journal
        data = stream_of_with_gaps(j, shim.terminal_id)
        assert b"Recovery" not in data
        gaps = [r.header for r in j.iter_events(kinds=["term.gap"])]
        assert {"terminal_id": shim.terminal_id, "stream_off": 16, "reason": "sensitive_output",
                "bytes_lost": 26} in gaps
        await shim.close()

    run(paths, operator, scenario, idle_flush=0.05)


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
        assert st["operator"]["unlocked"] and st["project"]["slug"] == "ok" and st["rec"] is False
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
        await ctl_ok(paths.ctl_sock, "rec.on")
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
        await ctl_ok(paths.ctl_sock, "rec.on")
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

    run(paths, operator, scenario, idle_flush=0.05)


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
