"""E104 durch den Daemon: INPUT-Rahmen mit Passwort-Flag, ``show inputs`` verdeckt,
``input.reveal`` nur ausdrücklich, eigene Secrets auch dann ersetzt (E72), Anzeige in der CLI."""

from __future__ import annotations

import time

from ariadne._shim import protocol as P
from ariadne.cli.views import render_input_revealed, render_view
from ariadne.ingest.inputs import MASK
from tests.core.conftest import OWN_SECRET
from tests.core.fakeshim import FakeShim, ctl, ctl_ok
from tests.integration.test_daemon_ingest import run


async def _input(s: FakeShim, seq: int, off: int, data: bytes, *, no_echo: bool = False) -> None:
    await s.send(P.encode_input(seq, off, off, time.time_ns(), time.monotonic_ns(), data, no_echo=no_echo))


def test_inputs_hidden_in_views_and_revealed_only_on_request(paths, operator):
    async def scenario(d) -> None:
        await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=["10.10.10.3"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        await s.outx(1, 0, b"$ ")
        await _input(s, 2, 2, b"id\r")
        await s.outx(3, 2, b"id\r\nuid=0(root)\r\n[sudo] Passwort: ")
        await _input(s, 4, 36, OWN_SECRET.encode() + b"\r", no_echo=True)  # lokale Passwortabfrage
        await s.outx(5, 36, b"\r\nPassword: ")
        await _input(s, 6, 48, b"remote-pw\r")  # Remote-Shell: kein Echo in der Ausgabe
        await s.outx(7, 48, b"\r\n$ ")
        await s.wait_ack(7)
        res = await ctl_ok(paths.ctl_sock, "show", what="inputs")
        items = res["items"]
        assert [(i["hidden"], i["reason"], i["text"]) for i in items] == [
            (False, None, "id"), (True, "tty_no_echo", MASK), (True, "no_echo_seen", MASK)]
        assert OWN_SECRET not in repr(res) and "remote-pw" not in repr(res)
        stored = [r for r in d.project.journal.iter_events(kinds=["term.input"])]
        assert stored[1].header.get("no_echo") is True and stored[1].body.startswith(OWN_SECRET.encode())
        assert "no_echo" not in stored[0].header  # nur gesetzt, wenn wahr (Kette unverändert)
        # Aufdecken: einzeln, eigene Secrets ersetzt der Ausgang trotzdem (E72)
        own = await ctl_ok(paths.ctl_sock, "input.reveal", seq=items[1]["seq"])
        assert own["item"]["revealed"] is True and OWN_SECRET not in own["item"]["text"]
        remote = await ctl_ok(paths.ctl_sock, "input.reveal", seq=items[2]["seq"])
        assert remote["item"]["text"] == "remote-pw"
        bad = await ctl(paths.ctl_sock, "input.reveal", seq=1)
        assert bad["error"]["code"] == "not_found"
        d.presentation = True  # Präsentationsmodus (E99): kein Aufdecken
        pres = await ctl(paths.ctl_sock, "input.reveal", seq=items[2]["seq"])
        assert pres["error"]["code"] == "policy"
        d.presentation = False
        lines = render_view("inputs", items)
        assert "id" in lines[0] and MASK in lines[1] and "Passwortabfrage" in lines[1]
        assert "--reveal" in lines[2] and "remote-pw" not in "\n".join(lines)
        assert "remote-pw" in "\n".join(render_input_revealed(remote["item"]))
        await s.close()

    run(paths, operator, scenario)
