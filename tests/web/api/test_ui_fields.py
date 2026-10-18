"""Additive Felder für die Oberfläche (web-api.md 18.8) über echte HTTP-Anfragen gegen den echten
Server: Lagebild «Stand», Ports und Kurzform eines Widerspruchs an Host-Karten und in der Tabelle,
Out-of-Scope-Hinweise mit erster Quelle, Herkunft des Zugriffs und erste Quelle im Host-Detail,
Banner und Herkunft an Services, Terminal-Bezug, Zeit und Logauszug an Kontextvorschlägen, Ergebnis
pro Befehl und Zielbezug von Entscheiden in der Zeitachse, Bruchstelle der Hash-Kette im Kopf einer
Einheit, Grösse und Grund in der Warteliste."""

from __future__ import annotations

import urllib.parse

import pytest

from ariadne.daemon.ingest import IngestService
from ariadne.web.api.search import PENDING_REASONS, _lsize, pending_reason
from tests.web.api.helpers import TARGET, build_fixture, sync
from tests.web.server.helpers import Web, run_web

pytestmark = pytest.mark.web

HOST = f"ip:default/{TARGET}"
HOST_Q = urllib.parse.quote(HOST, safe="")


def test_additive_fields_from_real_server(paths, operator):
    async def scenario(web: Web) -> None:
        d = web.d
        fx = await build_fixture(d, paths, extra=True)
        token = await web.login()
        base = f"/api/v1/p/{fx.pid}"

        async def get(path: str):
            r = await web.req("GET", base + path, token=token)
            assert r.status_code == 200, (path, r.text)
            return r.json()

        g = await get("/graph")
        assert g["as_of"].endswith("Z")
        (node,) = [n for n in g["nodes"] if n["kind"] == "host"]
        assert node["ports"] == sorted(node["ports"]) and len(node["ports"]) == 12 and node["ports"][0] == 21
        assert node["conflict_brief"] == {"predicate": "service.product", "port": 21}
        oos = {i["identifier"]: i for i in g["oos"]["items"]}
        cb = oos["ip:default/10.10.10.99"]
        assert cb["note"] == "forged_callback" and cb["related"] is None and cb["punycode"] is None
        assert cb["source"]["unit_id"] and cb["source"]["terminal_id"] == fx.extra["callback"]
        assert all(i["note"] in (None, "same_mac", "forged_callback") for i in g["oos"]["items"])
        # E129 (web-api.md 20.4): Vorschläge aus der Kennung, nur bei Urteil «out»
        assert cb["verdict"] == "out" and cb["proposals"] == [
            {"entry": "10.10.10.99", "kind": "ip", "outside_lab": False, "public": False}]
        assert all(i["proposals"] == [] for i in g["oos"]["items"] if i["verdict"] != "out")
        (summary,) = (await get("/hosts"))["hosts"]
        assert summary["ports"] == node["ports"] and summary["conflict_brief"] == node["conflict_brief"]

        det = await get(f"/hosts/{HOST_Q}")
        assert det["candidate_claims"] == [] and det["access_by"] is None
        assert det["first_source"]["unit_id"] and det["first_source"]["kind"] in (
            "command",
            "segment",
            "file",
        )
        svc = {s["port"]: s for s in det["services"]}
        assert svc[139]["banner"] == "workgroup: WORKGROUP"
        assert all(
            isinstance(s["from_target"], bool) and isinstance(s["suspect"], bool) for s in svc.values()
        )

        nx = await get("/next")
        (sug,) = [i for i in nx["clarify"] if i["kind"] == "ctx_suggestion"]
        assert sug["terminal"] == {"terminal_id": fx.extra["callback"], "ordinal": 4, "label": None}
        assert sug["from_ts"].endswith("Z") and "excerpt" in sug  # Auszug erst mit gespeicherten Zeilen
        # stabile Nummern der Klärungen («K2», 18.12): eindeutig, beim zweiten Abruf gleich
        ords = {i["item_key"]: i["ordinal"] for i in nx["clarify"]}
        assert all(isinstance(o, int) and o >= 1 for o in ords.values())
        assert len(set(ords.values())) == len(ords)
        again = await get("/next")
        assert {i["item_key"]: i["ordinal"] for i in again["clarify"]} == ords

        # Entscheide mit Zielbezug; Zugriff kommt danach «per Entscheid»
        r = await web.req(
            "POST",
            f"{base}/decisions",
            token=token,
            json_body={
                "decisions": [
                    {"kind": "d.status.access", "payload": {"subject": HOST, "value": "admin"}},
                    {
                        "kind": "d.terminal.label",
                        "payload": {"terminal_id": fx.shim.terminal_id, "label": "scan"},
                    },
                ]
            },
        )
        assert r.status_code == 201, r.text
        access_id = r.json()["results"][0]["decision_id"]
        await sync(d)
        det = await get(f"/hosts/{HOST_Q}")
        assert det["access"] == "admin" and det["access_by"]["source"] == "decision"
        assert det["access_by"]["decision_id"] == access_id and det["access_by"]["ts"].endswith("Z")

        tl = (await get("/timeline"))["items"]
        cmds = {i["cmd"]["text"]: i for i in tl if i["type"] == "command"}
        nm = cmds[f"nmap -sV -oA scans/lame {TARGET}"]
        assert nm["terminal"] == {"terminal_id": fx.shim.terminal_id, "ordinal": 1, "label": "scan"}
        assert nm["result"]["services"] == 23 and nm["result"]["values"] == nm["adopted"] > 0
        assert nm["result"]["conflicts"] >= 1
        # genau ein Befehl hat den Host zuerst gesehen (im Fixture liegen die Zeiten der Attrappe eng)
        assert sum(i["result"]["hosts_new"] for i in cmds.values()) == 1
        assert cmds["nc -lvnp 4445"]["result"]["out_of_scope"] >= 1
        assert cmds["nc -lvnp 4445"]["result"]["hosts_new"] == 0
        dec = next(i for i in tl if i["type"] == "decision" and i["decision_id"] == access_id)
        assert dec["detail"] == f"Zugriff root auf {TARGET}" and dec["effect"] is None and dec["ref"] is None
        assert all("terminal" in i for i in tl)
        for i in tl:
            if i["type"] == "context":  # 18.12: Host, Art und Benutzer einzeln
                assert {"host_label", "stage_kind", "user"} <= set(i)

        # Kopf einer Einheit: Terminal-Bezug; Bruchstelle der Kette nach einer Manipulation
        unit = await get(f"/units/{urllib.parse.quote(nm['unit_id'], safe='')}")
        assert (
            unit["terminal"]["ordinal"] == 1 and unit["chain_break_line"] is None and unit["chain_ok"] is True
        )
        assert unit["tty"] == "/dev/pts/7"  # Gerät aus term.open (Belegansicht «Quelle pts/7»)
        start = await d.ingest.query(
            lambda c: c.execute("SELECT start_off FROM unit WHERE unit_id = ?", (nm["unit_id"],)).fetchone()[
                0
            ]
        )
        ev = next(
            r
            for r in d.project.journal.iter_events(kinds=["term.out"], terminal_id=fx.shim.terminal_id)
            if r.stream_off is not None and r.stream_off + len(r.body or b"") > start + 40
        )
        conn = d.project.journal.conn
        conn.execute("DROP TRIGGER event_redact_only")  # wie ein Angreifer mit Zugriff auf die Datei
        conn.execute("UPDATE event SET body = ? WHERE seq = ?", (b"x" * len(ev.body or b"x"), ev.seq))
        conn.commit()
        unit = await get(f"/units/{urllib.parse.quote(nm['unit_id'], safe='')}")
        assert isinstance(unit["chain_break_line"], int) and unit["chain_ok"] is False

        pend = await get("/files/pending")
        assert pend == {"files": [], "truncated": False}
        for s in fx.shims:
            await s.close()

    run_web(paths, operator, scenario, ingest=IngestService(debounce=0.05, periodic=0))


def test_pending_reason_codes_and_size(tmp_path):
    for code in PENDING_REASONS:
        assert pending_reason(code) == code
    assert pending_reason("symlink_or_not_dir") == "symlink"
    assert pending_reason("missing") == "path" and pending_reason(None) == "path"
    f = tmp_path / "a.txt"
    f.write_bytes(b"12345")
    link = tmp_path / "link"
    link.symlink_to(f)
    assert _lsize(str(f), None) == 5 and _lsize("a.txt", tmp_path) == 5
    assert _lsize(str(link), None) is None  # lstat: Symlink, kein Folgen
    assert _lsize("gibts-nicht", tmp_path) is None and _lsize("a\0b", None) is None


def test_segment_evaluate_after_from_last_output():
    from ariadne.ingest.pipeline import SILENCE_NS
    from ariadne.web.api.text import Bag, iso
    from ariadne.web.api.timeline import _shape

    ctx = {"refs": {"t1": {"ordinal": 2, "label": "msf", "first_ts": 1}}, "last_out": {"t1": 10**18}}
    base = {
        "id": "u:t1@0",
        "type": "segment",
        "ts": 10**18,
        "terminal_id": "t1",
        "unit_id": "u:t1@0",
        "lines": 3,
    }
    open_seg = _shape({**base, "state": "provisional"}, ctx, Bag())
    assert open_seg["evaluate_after"] == iso(10**18 + SILENCE_NS)
    assert open_seg["terminal"] == {"terminal_id": "t1", "ordinal": 2, "label": "msf"}
    assert _shape({**base, "state": "final"}, ctx, Bag())["evaluate_after"] is None


def test_pending_paths_are_shown_like_in_the_terminal(tmp_path):
    """Warteliste (18.12): im Arbeitsordner relativ, unter HOME mit «~/», sonst unverändert."""
    from ariadne.web.api.search import _short_path

    home = tmp_path / "h"
    ws = home / "ariadne" / "ms2"
    assert _short_path(str(ws / "scans" / "udp.xml"), ws, home) == "scans/udp.xml"
    assert _short_path(str(home / "privat" / "notizen.txt"), ws, home) == "~/privat/notizen.txt"
    assert _short_path("/etc/passwd", ws, home) == "/etc/passwd"
    assert _short_path(str(home) + "x/datei", ws, home) == str(home) + "x/datei"  # kein Präfix-Treffer
    assert _short_path("relativ.txt", ws, home) == "relativ.txt"
    assert _short_path(None, ws, home) is None
