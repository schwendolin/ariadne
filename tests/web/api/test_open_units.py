"""Offene Einheiten (laufender Listener) in der Web-API: Logauszug «Darum mehrdeutig» am
Kontextvorschlag und Belegzeilen, bevor die Zeilen endgültig gespeichert sind (web-api.md 18.12,
``ariadne.ingest.pending``). Über echte HTTP-Anfragen gegen den echten Server mit Daemon und
Auswertung, FakeShim als Terminal."""

from __future__ import annotations

from pathlib import Path

import pytest

from ariadne.daemon.ingest import IngestService
from ariadne.ingest import pending
from tests.core.fakeshim import FakeShim, ctl_ok
from tests.integration.helpers import Term
from tests.web.api.helpers import sync
from tests.web.server.helpers import Web, run_web

pytestmark = pytest.mark.web

NET = "192.168.56.0/24"


def test_listener_with_second_callback_gives_excerpt_and_lines(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        res = await ctl_ok(paths.ctl_sock, "start", slug="ms2", targets=[NET])
        pid = str(res["id"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        t = Term(s)
        # zwei Meldungen des Listeners vor jeder Ausgabe des Ziels: die Stufe ist mehrdeutig
        await t.command(
            "nc -lvnp 4445",
            b"listening on [any] 4445 ...\r\n"
            b"connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 49158\r\n"
            b"connect to [192.168.56.102] from (UNKNOWN) [10.66.66.66] 31337\r\n"
            b"id\r\nuid=0(root) gid=0(root)\r\n",
            cwd=str(Path(res["workspace"])),
            end=False,
        )
        await t.acked()
        await sync(d)
        token = await web.login()
        r = await web.req("GET", f"/api/v1/p/{pid}/next", token=token)
        assert r.status_code == 200, r.text
        (item,) = [i for i in r.json()["clarify"] if i["kind"] in ("ctx_suggestion", "ctx_unknown")]
        assert item["kind"] == "ctx_suggestion"
        assert item["suggested_label"] == "192.168.56.101"
        assert item["reason_ts"] is not None and item["reason_ts"].endswith("Z")  # «um 16:52:31»
        ex = item["excerpt"]
        assert ex is not None, "Logauszug fehlt bei offener Einheit"
        assert ex["note"] == "second_callback"
        # wie im Design: genau die Zeile des zweiten Callbacks
        assert len(ex["text"]) == 1 and "[10.66.66.66] 31337" in ex["text"][0], ex["text"]
        assert ex["lines"][0] == ex["lines"][1]
        assert ex["ts"] is not None and ex["ts"].endswith("Z")
        # Belegansicht der offenen Einheit: Kopf mit Zeilenzahl, Zeilen über /lines
        unit = ex["unit_id"]
        u = await web.req("GET", f"/api/v1/p/{pid}/units/{unit}", token=token)
        assert u.status_code == 200, u.text
        assert u.json()["line_count"] >= 3
        lines = await web.req("GET", f"/api/v1/p/{pid}/units/{unit}/lines?from=0&count=50", token=token)
        assert lines.status_code == 200, lines.text
        body = lines.json()
        texts = [ln["text"] for ln in body["lines"]]
        assert body["total"] == len(texts) >= 3
        assert any("[192.168.56.101] 49158" in x for x in texts)
        # ausserhalb des Threads der Auswertung (keine gebundene Pipeline) gibt es keine vorläufigen Zeilen
        assert pending.pending_rows(None, unit) == []  # type: ignore[arg-type]

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))


def test_open_msf_segment_shows_held_back_output_in_timeline_and_evidence(paths, operator):
    """msfconsole öffnet eine Stufe: die Ausgabe gehört zum offenen Segment. Der letzte Block hält der
    Strom zurück (mögliche Grenze), trotzdem zeigen Zeitachse und Belegansicht seine Zeilen."""

    async def scenario(web: Web) -> None:
        d = web.d
        res = await ctl_ok(paths.ctl_sock, "start", slug="ms2", targets=[NET])
        pid = str(res["id"])
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        t = Term(s)
        # Zeile für Zeile wie msfconsole: den letzten Block hält der Strom zurück
        await t.command("msfconsole -q", b"", cwd=str(Path(res["workspace"])), end=False)
        for line in (
            b"msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run\r\n",
            b"[*] Started reverse TCP handler on 192.168.56.102:4444 \r\n",
            b"[+] 192.168.56.101:21 - UID: uid=0(root) gid=0(root)\r\n",
            b"[*] Found shell.\r\n",
            b"[*] Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.101:6200)\r\n",
        ):
            await t.out(line)
            await t.acked()
            await sync(d)
        await sync(d)
        token = await web.login()
        r = await web.req("GET", f"/api/v1/p/{pid}/timeline?types=segment,command&limit=50", token=token)
        assert r.status_code == 200, r.text
        segs = [i for i in r.json()["items"] if i["type"] == "segment"]
        assert len(segs) == 1, r.json()["items"]
        seg = segs[0]
        assert seg["state"] != "final"
        assert seg["lines"] >= 4
        u = await web.req("GET", f"/api/v1/p/{pid}/units/{seg['unit_id']}", token=token)
        assert u.status_code == 200, u.text
        body = u.json()
        assert body["kind"] == "segment" and body["state"] != "final"
        assert body["title"] == "msfconsole -q"  # Befehl, der die Stufe geöffnet hat
        # Kontext wie im Design «Kali › 192.168.56.101 [msf] (auto)»: der später erkannte Auto-Host
        (msf,) = [st for st in body["context"] if st["kind"] == "msf"]
        assert msf["host_label"] == "192.168.56.101" and msf["auto"] is True
        assert body["line_count"] >= 4
        lines = await web.req(
            "GET", f"/api/v1/p/{pid}/units/{seg['unit_id']}/lines?from=0&count=50", token=token
        )
        texts = [ln["text"] for ln in lines.json()["lines"]]
        assert any("Command shell session 1 opened" in x for x in texts), texts
        assert any("UID: uid=0(root)" in x for x in texts), texts

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))
