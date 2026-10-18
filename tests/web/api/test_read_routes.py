"""Lesende Routen mit dem MS2-Fixture gegen den echten Daemon (Vertrag v0.1-Server 4): Status,
Terminals, Projekt, Änderungen, Karte, Hosts, Services, Als Nächstes, Zeitachse, Eingaben (E104),
Belege, Logzeilen, Suche, Warteliste, Positionen."""

from __future__ import annotations

import urllib.parse

from ariadne.web.api.text import MASK
from tests.web.api.helpers import BASE, CRYPT, HOSTILE, OWN_SECRET, REMOTE_PW, TARGET, clean, run_api

HOST = f"ip:default/{TARGET}"
HOST_Q = urllib.parse.quote(HOST, safe="")


def test_status_terminals_project_and_changes(paths, operator):
    async def body(d, c, fx, bus, ctx):
        r = await c.get(f"{BASE}/status")
        assert r.status_code == 200 and r.headers["content-type"] == "application/json; charset=utf-8"
        st = r.json()
        assert st["api_version"] == 2 and st["session"]["origin"] == "sshd" and st["session"]["session_id"]
        assert st["project"] == {
            "id": fx.pid,
            "slug": "lame",
            "name": "lame",
            "profile": "lab",
            "chain_head_ok": True,
        }
        assert st["operator"] == {"exists": True, "unlocked": True} and st["locked"] is False
        assert st["active"] == {"slug": "lame", "stopped": False, "end_reason": None}
        assert st["recording"] == {"connected": 2, "on": 2, "paused": 0, "held": 0, "mux": 0}
        assert set(st["preroll"]) == {
            "terminals",
            "seconds",
            "window_s",
            "ask_terminals",
            "ask_seconds",
            "outage_terminals",
            "outage_seconds",
        }
        assert isinstance(st["generation"], int) and st["generation"] >= 1
        assert st["presentation"] is False and st["llm"]["mode"] == "off" and st["disk_low"] is False
        assert st["llm"]["budget"] == {"month_limit_usd": 20.0, "month_used_usd": 0.0}
        assert st["idle"]["end_after_s"] > 0 and st["scope_warning"] is None
        terms = {t["terminal_id"]: t for t in st["terminals"]}
        t1 = terms[fx.shim.terminal_id]
        assert t1["short_id"] == fx.shim.terminal_id[-8:] and t1["state"] == "on"
        assert t1["context_label"] == f"Kali › {TARGET} [revshell] (auto)"
        assert terms[fx.shim2.terminal_id]["context_label"] == "Kali"

        r = await c.get(f"{BASE}/terminals")
        terms = {t["terminal_id"]: t for t in r.json()["terminals"]}
        t1 = terms[fx.shim.terminal_id]
        assert [s["kind"] for s in t1["stack"]] == ["local", "revshell"]
        assert t1["stack"][1]["host_id"] == HOST and t1["stack"][1]["auto"] is True
        assert t1["stack"][0]["host_label"] == "Kali" and t1["shell"] == "zsh" and t1["connected"] is True
        assert t1["last_command"]["text"] == "nc -lvnp 4444" and t1["last_command"]["ended_at"] is None
        assert t1["last_command"]["cmd_ref"].startswith(fx.shim.terminal_id[-8:] + "@")
        assert t1["remote_segment"] is not None and t1["suggestion"] is None
        t2 = terms[fx.shim2.terminal_id]
        assert t2["remote_segment"] is None and t2["last_command"] is None and len(t2["stack"]) == 1

        r = await c.get(f"{BASE}/p/{fx.pid}/project")
        pj = r.json()
        assert pj["id"] == fx.pid and pj["scope"] == {"include": [TARGET], "exclude": [], "version": 1}
        assert pj["lab_guard"] == {"public_targets": False, "confirmed_not_customer": False}
        assert pj["chain"]["head_seq"] > 0 and len(pj["chain"]["head_hash"]) == 64 and pj["chain"]["head_ok"]
        assert pj["created_at"].endswith("Z") and pj["started_at"].endswith("Z")
        assert (await c.get(f"{BASE}/p/0000000000000000/project")).json()["error"][
            "code"
        ] == "project_mismatch"
        assert (await c.get(f"{BASE}/p/x/project")).status_code == 409

        r = await c.get(f"{BASE}/p/{fx.pid}/changes", params={"since": 0})
        ch = r.json()
        assert ch["project_id"] == fx.pid and ch["from"] == 0 and ch["to"] == st["generation"]
        assert ch["reset"] is False and {x["entity"] for x in ch["changes"]} >= {"claim", "host"}
        assert (await c.get(f"{BASE}/p/{fx.pid}/changes", params={"since": 10**9})).json()["reset"] is True
        assert (await c.get(f"{BASE}/p/{fx.pid}/changes", params={"since": ch["to"]})).json()["changes"] == []
        for bad in ({"since": -1}, {}, {"since": "x"}):
            r = await c.get(f"{BASE}/p/{fx.pid}/changes", params=bad)
            assert r.status_code == 422 and r.json()["error"]["code"] == "validation"

    run_api(paths, operator, body)


def test_map_hosts_services_and_next(paths, operator):
    async def body(d, c, fx, bus, ctx):
        g = (await c.get(f"{BASE}/p/{fx.pid}/graph")).json()
        nodes = {n["id"]: n for n in g["nodes"]}
        assert g["project_id"] == fx.pid and nodes["kali"]["kind"] == "kali"
        host = nodes[HOST]
        assert host["kind"] == "host" and host["claim_state"] == "auto" and host["knowledge"] == "versions"
        assert host["segment"] == "seg:10.10.10.0/24" and nodes["seg:10.10.10.0/24"]["origin"] == "observed"
        assert host["services_total"] == 23 and sum(host["service_classes"].values()) == 23
        assert host["conflicts"] == 2 and host["hint"] == "conflict" and host["auto"] is True
        assert "ip:default/10.10.10.99" not in nodes  # ausserhalb des Scopes nie als Knoten
        assert any(i["identifier"] == "ip:default/10.10.10.99" for i in g["oos"]["items"])
        assert g["oos"]["total"] >= 1 and g["summary"]["hosts"] == 1 and g["summary"]["conflicts"] == 2
        ftp = nodes[f"svc:{HOST}|tcp/21"]
        assert ftp["class"] == "file" and ftp["ctrl"] is True and "<U+202E>" in ftp["product"]
        for e in g["edges"]:
            assert e["source"] in nodes and e["target"] in nodes
        assert not [e for e in g["edges"] if e["kind"] == "thread"] and g["table_only"] is False
        g2 = (await c.get(f"{BASE}/p/{fx.pid}/graph", params={"layers": "topology"})).json()
        assert {n["kind"] for n in g2["nodes"]} == {"kali", "segment", "host"} and g2["oos"]["total"] == 0
        r = await c.get(f"{BASE}/p/{fx.pid}/graph", params={"layers": "topology,bogus"})
        assert r.status_code == 422

        hosts = (await c.get(f"{BASE}/p/{fx.pid}/hosts")).json()["hosts"]
        assert [h["id"] for h in hosts] == [HOST] and "kind" not in hosts[0]
        assert set(hosts[0]["quiet"]) >= {"heuristic", "out_of_scope", "mentions", "system_accounts"}
        det = (await c.get(f"{BASE}/p/{fx.pid}/hosts/{HOST_Q}")).json()
        ids = {i["key"]: i for i in det["identifiers"]}
        assert ids[HOST]["verdict"] == "in" and ids["fqdn:irc.metasploitable.lan"]["verdict"] == "out"
        assert len(det["services"]) == 23 and len(det["facts"]) > 100 and not det["facts_truncated"]
        assert {k["predicate"] for k in det["conflicts"]} == {"service.product", "service.version"}
        assert all(k["state"] == "open" and len(k["values"]) == 2 for k in det["conflicts"])
        assert {i for i in det["open_items"] if i.startswith("conflict:")} and det["note"] is None
        fact = next(f for f in det["facts"] if f["predicate"] == "service.product" and f["ctrl"])
        assert fact["value"].startswith("<script>") and "\u202e" not in fact["value"]
        assert (await c.get(f"{BASE}/p/{fx.pid}/hosts/ip%3Adefault%2F1.2.3.4")).status_code == 404

        svcs = (await c.get(f"{BASE}/p/{fx.pid}/services", params={"class": "smb"})).json()["services"]
        assert [s["port"] for s in svcs] == [139, 445]
        s445 = svcs[1]
        assert s445["version"] == "3.0.20-Debian" and s445["verdict"] == "in"
        assert {(h["predicate"], h["value"]) for h in s445["history"]} >= {("service.version", "3.X - 4.X")}
        allsv = (await c.get(f"{BASE}/p/{fx.pid}/services", params={"host": HOST})).json()["services"]
        assert len(allsv) == 23
        assert (await c.get(f"{BASE}/p/{fx.pid}/services", params={"class": "bogus"})).status_code == 422

        nx = (await c.get(f"{BASE}/p/{fx.pid}/next")).json()
        kinds = sorted(i["kind"] for i in nx["clarify"])
        assert kinds == ["conflict", "conflict", "ctx_suggestion"] and nx["open"] == 3
        assert nx["confirm"] == [] and nx["suggestions"] == [] and nx["suggestions_available"] is False
        sug = next(i for i in nx["clarify"] if i["kind"] == "ctx_suggestion")
        assert (
            sug["terminal_id"] == fx.extra["callback"] and sug["suggested_host"] == "ip:default/10.10.10.99"
        )
        assert sug["reason"].startswith("Callback von 10.10.10.99") and sug["stage_kind"] == "revshell"
        conf = next(
            i
            for i in nx["clarify"]
            if i["kind"] == "conflict" and i["conflict"]["predicate"] == "service.product"
        )
        values = {v["value"] for v in conf["conflict"]["values"]}
        assert "ProFTPD" in values and any(v.startswith("<script>") for v in values)
        assert set(nx["quiet"]) == {"heuristic", "out_of_scope", "mentions", "system_accounts", "own_address"}
        # Kontextvorschlag auch am Terminal
        terms = {t["terminal_id"]: t for t in (await c.get(f"{BASE}/terminals")).json()["terminals"]}
        assert terms[fx.extra["callback"]]["suggestion"]["item_key"] == sug["item_key"]

    run_api(paths, operator, body, extra=True)


def test_timeline_inputs_evidence_search(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}"
        tl = (await c.get(f"{P}/timeline", params={"limit": 1000})).json()
        items = tl["items"]
        assert tl["next_cursor"] is None and len({i["id"] for i in items}) == len(items)
        types = {i["type"] for i in items}
        assert {"command", "file", "context", "decision", "project"} <= types and "input" not in types
        nmap = next(i for i in items if i["type"] == "command" and i["cmd"]["text"].startswith("nmap"))
        assert nmap["adopted"] >= 50 and nmap["distrusted"] is None and nmap["scope_warning"] is None
        assert [f["path"] for f in nmap["files"]] == ["scans/lame.xml"] and nmap["lines"] > 50
        assert nmap["cmd"]["exit"] == 0 and nmap["cmd"]["ended_at"] and nmap["host_id"] is None
        auto = next(i for i in items if i["type"] == "context")
        assert auto["change"] == "auto" and auto["host_id"] == HOST and auto["source"] == "auto"
        assert next(i for i in items if i["type"] == "project")["change"] == "start"
        assert next(i for i in items if i["type"] == "decision")["summary"] == "Scope gesetzt (Version 1)"
        ts = [int(i["ts_ns"]) for i in items if i["type"] == "command"]
        assert ts == sorted(ts, reverse=True)  # neueste zuerst

        # Paginierung: Seiten zu 2 ergeben dieselbe Liste
        seen: list[str] = []
        cursor = None
        while True:
            params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
            page = (await c.get(f"{P}/timeline", params=params)).json()
            seen += [i["id"] for i in page["items"]]
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert seen == [i["id"] for i in items]
        for bad in (
            {"types": "command,bogus"},
            {"cursor": "!!"},
            {"limit": 0},
            {"limit": 1001},
            {"terminal": "x"},
        ):
            assert (await c.get(f"{P}/timeline", params=bad)).status_code == 422
        only = (await c.get(f"{P}/timeline", params={"terminal": fx.shim.terminal_id})).json()["items"]
        assert only and all(i["terminal_id"] == fx.shim.terminal_id for i in only)
        hosted = (await c.get(f"{P}/timeline", params={"host": HOST})).json()["items"]
        assert hosted and all(i["host_id"] == HOST for i in hosted)

        # Eingaben (E104): in der Zeitachse nur auf Wunsch, verdeckt
        ins = (await c.get(f"{P}/timeline", params={"types": "input"})).json()["items"]
        assert [i["input"]["text"] for i in ins] == [MASK, MASK, "id"]
        r = (await c.get(f"{P}/inputs")).json()["items"]
        assert [(i["hidden"], i["reason"], i["text"]) for i in r] == [
            (False, None, "id"),
            (True, "tty_no_echo", MASK),
            (True, "no_echo_seen", MASK),
        ]
        assert all(i["revealed"] is False and i["terminal_id"] == fx.shim2.terminal_id for i in r)
        assert len((await c.get(f"{P}/inputs", params={"limit": 1})).json()["items"]) == 1
        assert (await c.get(f"{P}/inputs", params={"terminal": fx.shim.terminal_id})).json()["items"] == []
        assert (await c.get(f"{P}/inputs", params={"limit": 5000})).status_code == 422

        # Belege eines Werts: Terminal und Datei, Zeilen
        det = (await c.get(f"{P}/hosts/{HOST_Q}")).json()
        fact = next(
            f for f in det["facts"] if f["predicate"] == "service.version" and f["subject"].endswith("/22")
        )
        src = (await c.get(f"{P}/facts/{fact['claim_key']}/sources")).json()
        assert src["fact"]["claim_key"] == fact["claim_key"]
        kinds = {s["t"] for s in src["sources"]}
        assert kinds == {"stream", "file"}
        stream = next(s for s in src["sources"] if s["t"] == "stream")
        assert stream["cmd"]["text"].startswith("nmap") and stream["context"][0]["host_label"] == "Kali"
        a, b = stream["lines"]
        lines = (
            await c.get(f"{P}/units/{stream['unit_id']}/lines", params={"from": a, "count": b - a + 1})
        ).json()
        assert "22/tcp" in lines["lines"][0]["text"] and lines["from"] == a
        filesrc = next(s for s in src["sources"] if s["t"] == "file")
        assert filesrc["path"] == "scans/lame.xml" and len(filesrc["sha256"]) == 64
        assert (await c.get(f"{P}/facts/{'0' * 64}/sources")).status_code == 404
        assert (await c.get(f"{P}/facts/xyz/sources")).status_code == 404

        # Einheit und Logzeilen mit verdeckten Bereichen
        cat = next(i for i in items if i["type"] == "command" and i["cmd"]["text"] == "cat loot.txt")
        unit = (await c.get(f"{P}/units/{cat['unit_id']}")).json()
        assert (
            unit["kind"] == "command" and unit["exit"] == 0 and unit["line_count"] == 4 and unit["chain_ok"]
        )
        ls = (await c.get(f"{P}/units/{cat['unit_id']}/lines")).json()
        assert ls["total"] == 4 and [ln["n"] for ln in ls["lines"]] == [0, 1, 2, 3]
        assert ls["lines"][0]["prompt_echo"] is True
        assert ls["lines"][1]["text"] == f"admin:{MASK}:18000:0:99999:7:::"
        assert ls["lines"][1]["masked"] == [{"col_start": 6, "col_end": 14, "kind": "secret"}]
        assert (
            ls["lines"][2]["text"] == f"sudo {MASK}" and ls["lines"][2]["masked"][0]["kind"] == "own_secret"
        )
        assert ls["lines"][3]["ctrl"] is True and "<U+202E>" in ls["lines"][3]["text"]
        assert (await c.get(f"{P}/units/{cat['unit_id']}/lines", params={"count": 2001})).status_code == 422
        assert (await c.get(f"{P}/units/u:nichts@1/lines")).status_code == 404
        assert (await c.get(f"{P}/units/u:nichts@1")).status_code == 404
        log = await c.get(f"{P}/units/{cat['unit_id']}/log.txt")
        assert log.status_code == 200 and log.headers["content-type"] == "text/plain; charset=utf-8"
        disp = log.headers["content-disposition"]
        assert disp.startswith('attachment; filename="unit-') and "loot" not in disp
        assert (
            CRYPT not in log.text
            and OWN_SECRET not in log.text
            and MASK in log.text
            and "<U+202E>" in log.text
        )

        # Steuerzeichen direkt aus der Ausgabe: sichtbar, ctrl gesetzt
        c1 = next(i for i in items if i["type"] == "command" and i["cmd"]["text"] == "cat c1.txt")
        ln = (await c.get(f"{P}/units/{c1['unit_id']}/lines")).json()["lines"][-1]
        assert ln["ctrl"] is True and "<U+202E>ltr" in ln["text"] and "<U+200B>zw" in ln["text"]
        assert clean(ln["text"]) and ln["text"].startswith("c1 ")

        # Volltextsuche: Zeile wie in /lines
        res = (await c.get(f"{P}/search", params={"q": "banner"})).json()
        assert res["truncated"] is False and len(res["items"]) == 1
        hit = res["items"][0]
        assert hit["unit_id"] == cat["unit_id"] and hit["line"] == 3 and hit["ctrl"] is True
        assert hit["cmd"] == "cat loot.txt" and hit["context_label"] == "Kali"
        res = (await c.get(f"{P}/search", params={"q": "admin"})).json()
        assert CRYPT not in str(res) and MASK in res["items"][0]["text"]
        for bad in ({"q": ""}, {"q": "x" * 201}, {"q": "a", "limit": 500}, {}):
            assert (await c.get(f"{P}/search", params=bad)).status_code == 422
        assert (await c.get(f"{P}/search", params={"q": "nmap", "limit": 1})).json()["truncated"] is True
        assert (await c.get(f"{P}/files/pending")).json() == {"files": [], "truncated": False}
        # Eingaben und Ausgaben enthalten nie Secrets im Klartext
        for text in (str(tl), str(r), str(ls), str(unit)):
            assert REMOTE_PW not in text and OWN_SECRET not in text and CRYPT not in text
        assert HOSTILE not in str(ls)  # nur sichtbar gemacht

    run_api(paths, operator, body)


def test_positions_roundtrip_and_limits(paths, operator):
    async def body(d, c, fx, bus, ctx):
        P = f"{BASE}/p/{fx.pid}/ui/positions"
        assert (await c.get(P)).json() == {"positions": {}, "updated_at": None}
        r = await c.put(P, json={"positions": {"kali": {"x": 1.5, "y": -2}, HOST: {"x": 10, "y": 20}}})
        assert r.status_code == 202 and r.json() == {"accepted": True}
        got = (await c.get(P)).json()
        assert got["positions"] == {"kali": {"x": 1.5, "y": -2.0}, HOST: {"x": 10.0, "y": 20.0}}
        assert got["updated_at"].endswith("Z")
        await c.put(P, json={"positions": {"kali": {"x": 0, "y": 0}}})  # ersetzt alles
        assert list((await c.get(P)).json()["positions"]) == ["kali"]
        many = {f"n{i}": {"x": 0, "y": 0} for i in range(5001)}
        for bad in (
            {"positions": many},
            {"positions": {"a": {"x": 1}}},
            {"positions": {"a": {"x": 1, "y": 2, "z": 3}}},
            {"positions": {"a": {"x": "1", "y": 2}}},
            {"positions": {}, "extra": 1},
        ):
            r = await c.put(P, json=bad)
            assert r.status_code == 422, bad
        r = await c.put(
            P,
            content=b'{"positions": {"a": {"x": Infinity, "y": 1}}}',
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 422
        assert (await c.get(P.replace(fx.pid, "0" * 16))).status_code == 409

    run_api(paths, operator, body, extra=False)


def test_scope_warning_in_status_and_timeline(paths, operator):
    """E67: Befehl mit einem Ziel ausserhalb des Scopes: Kennzeichen im Status und am Befehl."""
    from tests.core.fakeshim import FakeShim, ctl_ok
    from tests.integration.helpers import Term
    from tests.web.api.helpers import sync

    async def body(d, c, fx, bus, ctx):
        res = await ctl_ok(paths.ctl_sock, "start", slug="lame", targets=[TARGET])
        assert (await c.get(f"{BASE}/status")).json()["scope_warning"] is None
        s = await FakeShim(paths.term_sock).connect(proto=2)
        await s.wait_state(rec="on")
        t = Term(s)
        await t.command("nmap -sn 10.10.10.99", b"Nmap done: 1 IP address (0 hosts up)\r\n", cwd="/tmp")
        await t.acked()
        await sync(d)
        st = (await c.get(f"{BASE}/status")).json()
        warn = st["scope_warning"]
        assert warn["terminal_id"] == s.terminal_id and warn["cmd_ref"].startswith(s.terminal_id[-8:] + "@")
        tl = (await c.get(f"{BASE}/p/{res['id']}/timeline")).json()["items"]
        cmd = next(i for i in tl if i["type"] == "command")
        assert cmd["cmd"]["cmd_id"] == warn["cmd_id"]
        assert cmd["scope_warning"] == {"targets": [{"value": "10.10.10.99", "verdict": "out"}]}
        await s.close()

    run_api(paths, operator, body, fixture=False)
