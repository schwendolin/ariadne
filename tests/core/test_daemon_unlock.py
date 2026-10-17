"""Entscheide vom 2026-10-15 zum Entsperren (E101 bis E103), Fake-Shims über echte Sockets.

* E101: ``unlock`` bei aktivem Projekt öffnet es wie ``start`` ohne Slug; Status und
  Titel stimmen danach (Befund F3 aus dem letzten Bau: es blieb «locked»).
* E102: Den Ausfallpuffer nach einem Neustart übernehmen ``start`` und ``unlock`` ohne
  Rückfrage; der Vorlauf ohne Projekt bleibt eine Frage.
* E103: ``lock`` sperrt nur, das Projekt bleibt aktiv; bis zum nächsten ``start`` oder
  ``unlock`` wird nichts gespeichert.
"""

from __future__ import annotations

import json
import shutil
from typing import Any

from tests.core.conftest import PASSPHRASE
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.core.test_daemon import run
from tests.core.test_daemon_capture import backup_of, headers
from tests.core.test_daemon_review import covered


def _stream(journal, tid: str) -> bytes:
    return b"".join(r.body for r in journal.iter_events(kinds=["term.out"], terminal_id=tid))


def test_lock_keeps_project_active_and_stores_nothing_until_unlock(paths, operator):
    """E103 und E101: ``lock`` lässt das Projekt aktiv; ``unlock`` öffnet es wieder, die Aufnahme
    läuft sofort. Die gesperrte Zeit ist Vorlauf (Frage, hier Nein) und fehlt als no_project."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"vorher\r\n")
        await s.wait_ack(1)
        res = await ctl_ok(paths.ctl_sock, "lock")
        assert res == {"closed_project": True}
        assert json.loads(paths.active_file.read_text())["stopped"] is False
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["project"] is None and st["locked"] is True
        assert st["active"] == {"slug": "lame", "stopped": False}
        assert [t["state"] for t in st["terminal_states"]] == ["locked"]
        await s.wait_state(rec="locked", project=None)
        await s.outx(2, 8, b"gesperrt\r\n")  # nur im RAM
        await s.wait_ack(2)
        info = await ctl_ok(paths.ctl_sock, "preroll.info")
        assert info["ask_terminals"] == 1 and info["outage_terminals"] == 0  # nach lock: Frage
        res = await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE)
        assert res["already"] is False and res["reopened"]["slug"] == "lame"
        assert res["reopened"]["preroll"]["discarded_terminals"] == 1
        await s.wait_state(rec="on", project="lame")
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["project"]["slug"] == "lame" and st["locked"] is False
        assert [t["state"] for t in st["terminal_states"]] == ["on"]
        await s.outx(3, 18, b"danach\r\n")
        await s.wait_ack(3)
        d.flush()
        j = d.project.journal
        assert _stream(j, s.terminal_id) == b"vorher\r\ndanach\r\n"
        assert (8, 10, "no_project") in covered(j, s.terminal_id)
        ends = [h["reason"] for h in headers(j, "system.project_end")]
        assert ends == ["lock"]
        await s.close()

    run(paths, operator, scenario)


def test_unlock_with_yes_adopts_locked_time(paths, operator):
    """Nach ``lock`` übernimmt ``unlock`` die gesperrte Zeit, wenn der Nutzer ja sagt."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await ctl_ok(paths.ctl_sock, "lock")
        await s.wait_state(rec="locked")
        await s.outx(1, 0, b"gesperrt\r\n")
        await s.wait_ack(1)
        res = await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE, adopt_preroll=True)
        pre = res["reopened"]["preroll"]
        assert pre["adopted"] is True and pre["terminals"] == 1 and pre["outage_terminals"] == 0
        await s.wait_state(rec="on")
        d.flush()
        assert _stream(d.project.journal, s.terminal_id) == b"gesperrt\r\n"
        await s.close()

    run(paths, operator, scenario)


def test_unlock_after_restart_opens_project_and_adopts_outage(paths, operator):
    """E101 und E102 nach einem Absturz: Der neue Daemon startet gesperrt, das Projekt ist aktiv.
    ``unlock`` (ohne ``adopt_preroll``) öffnet es und übernimmt den Ausfallpuffer des gebundenen
    Terminals und eines neuen Terminals ohne Rückfrage, lückenlos."""
    state: dict[str, Any] = {}
    tid = "term-unlock-00001"

    async def first(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        state["pid"] = d.project.info.id
        s = await FakeShim(paths.term_sock, tid).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"vorher\r\n")
        await s.wait_ack(1)
        await s.close()

    async def second(d) -> None:
        s = await FakeShim(paths.term_sock, tid).connect(proto=2, resume_from_seq=2,
                                                        bound_project_id=state["pid"], bound_slug="lame")
        await s.wait_state(rec="locked")
        await s.outx(2, 8, b"im Ring\r\n")
        neu = await FakeShim(paths.term_sock).connect(proto=2)
        await neu.wait_state(rec="locked")
        await neu.outx(1, 0, b"neues Terminal\r\n")
        await s.wait_ack(2)
        await neu.wait_ack(1)
        st = await ctl_ok(paths.ctl_sock, "status")
        assert st["preroll"]["outage_terminals"] == 2 and st["preroll"]["ask_terminals"] == 0
        res = await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE)
        pre = res["reopened"]["preroll"]
        assert pre["outage_terminals"] == 2 and pre["discarded_terminals"] == 0, pre
        await s.wait_state(rec="on")
        await neu.wait_state(rec="on")
        await s.outx(3, 17, b"danach\r\n")
        await s.wait_ack(3)
        d.flush()
        j = d.project.journal
        assert _stream(j, tid) == b"vorher\r\nim Ring\r\ndanach\r\n"
        assert not any(p[2] in ("daemon_down", "no_project") for p in covered(j, tid))
        assert _stream(j, neu.terminal_id) == b"neues Terminal\r\n"
        await s.close()
        await neu.close()

    state["backup"] = backup_of(operator)
    run(paths, operator, first)
    run(paths, None, second)


def test_unlock_without_active_project_only_unlocks(paths, operator):
    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        await ctl_ok(paths.ctl_sock, "stop")
        res = await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE)
        assert res["reopened"] is None and "reopen_error" not in res
        assert d.project is None and d.operator is not None
        # schon entsperrt und nichts aktiv: bleibt so
        res = await ctl_ok(paths.ctl_sock, "unlock")
        assert res["already"] is True and res["reopened"] is None

    run(paths, operator, scenario)


def test_unlock_with_missing_project_folder_reports_and_stays_unlocked(paths, operator):
    async def scenario(d) -> None:
        res = await ctl_ok(paths.ctl_sock, "start", slug="weg", targets=["10.10.10.3"])
        ws = res["workspace"]
        await ctl_ok(paths.ctl_sock, "lock")
        shutil.rmtree(ws)
        res = await ctl_ok(paths.ctl_sock, "unlock", passphrase=PASSPHRASE)
        assert res["reopened"] is None and res["reopen_error"]["code"] == "no_active_project"
        assert d.operator is not None and d.project is None
        active = json.loads(paths.active_file.read_text())
        assert active["stopped"] is True and active["end_reason"] == "missing"

    run(paths, operator, scenario)


def test_unlock_when_already_unlocked_opens_active_project(paths, operator):
    """F3: entsperrt, aber das aktive Projekt ist nicht offen (z. B. Öffnen scheiterte vorher):
    ``unlock`` öffnet es jetzt, statt «schon entsperrt» zu melden und «locked» zu bleiben."""

    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        backup = backup_of(operator)
        await ctl_ok(paths.ctl_sock, "lock")
        d.operator = backup  # entsperrt ohne Öffnen (wie ein alter Daemon nach unlock)
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="locked")
        res = await ctl_ok(paths.ctl_sock, "unlock")
        assert res["already"] is True and res["reopened"]["slug"] == "lame"
        await s.wait_state(rec="on", project="lame")
        await s.close()

    run(paths, operator, scenario)


def test_start_after_restart_without_slug_needs_no_question(paths, operator):
    """E102 auch für ``start``: ohne Projektnamen, ohne ``adopt_preroll``, Ausfallpuffer übernommen."""
    state: dict[str, Any] = {}
    tid = "term-unlock-00002"

    async def first(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        state["pid"] = d.project.info.id
        s = await FakeShim(paths.term_sock, tid).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"a\r\n")
        await s.wait_ack(1)
        await s.close()

    async def second(d) -> None:
        s = await FakeShim(paths.term_sock, tid).connect(proto=2, resume_from_seq=2,
                                                        bound_project_id=state["pid"], bound_slug="lame")
        await s.wait_state(rec="locked")
        await s.outx(2, 3, b"b\r\n")
        await s.wait_ack(2)
        res = await ctl_ok(paths.ctl_sock, "start", passphrase=PASSPHRASE)
        assert res["unlocked"] and res["preroll"]["outage_terminals"] == 1
        d.flush()
        assert _stream(d.project.journal, tid) == b"a\r\nb\r\n"
        await s.close()

    run(paths, operator, first)
    run(paths, None, second)
