"""Praxistest 2 (E131, E133) mit echtem Daemon und der echten CLI: neues Projekt ohne ``--target``
(ohne Terminal nur mit ``--open-scope --not-customer``), nmap auf eine private und eine öffentliche
Adresse, curl auf einen öffentlichen Namen: keine Scope-Warnung, Hosts auf der Karte (auto). Danach
Ausschluss, ``scope add`` ergänzt den offenen Scope, ``scope close`` bringt die Warnung zurück,
``scope undo`` öffnet wieder. Eigene Adressen der Kali (E42) und Sonderadressen werden auch bei
offenem Scope nie Host. Dazu ``broad`` (E133) im dry_run."""

from __future__ import annotations

import asyncio
from typing import Any

from tests.core.fakeshim import FakeShim, ctl_ok
from tests.integration.helpers import Term
from tests.web.api.helpers import BASE, run_api, sync

NET = "10.36.198.0/24"
PRIV = "10.36.198.11"
PUB = "8.8.8.8"
GH = "https://github.com/"
KALI_PRIV = "10.36.198.5"
KALI_PUB = "198.51.100.7"  # eigene Adresse der Kali (z. B. VPN), öffentlich


def _nmap(*hosts: tuple[str, str]) -> bytes:
    out = "Starting Nmap 7.94 ( https://nmap.org )\r\n"
    for ip, svc in hosts:
        out += (f"Nmap scan report for {ip}\r\nHost is up (0.010s latency).\r\n"
                f"PORT   STATE SERVICE VERSION\r\n{svc}\r\n\r\n")
    out += f"Nmap done: {len(hosts)} IP addresses ({len(hosts)} hosts up) scanned in 1.00 seconds\r\n"
    return out.encode()


def _host(graph: dict[str, Any], ip: str) -> dict[str, Any] | None:
    return next((n for n in graph["nodes"] if n.get("kind") == "host" and ip in (n.get("addresses") or [])),
                None)


async def _lane(d: Any, ip: str) -> tuple[str, str, str] | None:
    return await d.ingest.query(lambda c: c.execute(
        "SELECT lane, lane_reason, state FROM claim WHERE predicate = 'host.address' AND value_text = ? "
        "ORDER BY lane = 'auto' DESC LIMIT 1", (ip,)).fetchone())


def _targets(nx: dict[str, Any]) -> list[str]:
    w = nx.get("scope_warning")
    return [t["value"] for t in w["targets"]] if w else []


def test_praxis2_open_scope_with_cli_and_daemon(paths, operator, capsys):
    from ariadne.cli.main import main

    async def cli(*argv: str) -> tuple[int, str]:
        capsys.readouterr()
        rc = await asyncio.to_thread(main, list(argv))
        return rc, capsys.readouterr().out + capsys.readouterr().err

    async def body(d, c, _fx, _bus, _ctx) -> None:
        # ohne Terminal und ohne Schalter: nichts angelegt (Tippfehlerschutz), Hinweis auf die Schalter
        rc, out = await cli("start", "praxis2")
        assert rc != 0 and d.project is None
        rc, out = await cli("start", "praxis2", "--open-scope")
        assert rc != 0 and d.project is None
        rc, out = await cli("start", "praxis2", "--open-scope", "--not-customer")
        assert rc == 0, out
        assert "Scope: offen" in out
        p = d.project
        assert p is not None and p.info.slug == "praxis2"
        assert p.settings["scope"]["open"] is True and p.settings["scope"]["include"] == []
        pid = p.info.id
        base = f"{BASE}/p/{pid}"
        rc, out = await cli("scope")
        first = out.splitlines()[0]
        assert rc == 0 and first == "Scope: offen (alles gilt als im Scope, ausser Ausschlüssen)"
        rc, out = await cli("status")
        assert rc == 0, out
        assert any(ln.startswith("Scope:") and ln.split()[1] == "offen" for ln in out.splitlines()), out

        shim = await FakeShim(paths.term_sock).connect(proto=2)
        try:
            await shim.wait_state(rec="on")
            term = Term(shim)
            ws = str(p.info.workspace)
            await term.command(f"nmap -sV {PRIV} {PUB}", _nmap(
                (PRIV, "22/tcp open  ssh     OpenSSH 8.9p1"),
                (PUB, "53/tcp open  domain  Google Public DNS")), cwd=ws)
            await term.command(f"curl {GH}", b"<html><title>GitHub</title></html>\r\n", cwd=ws)
            await term.acked()
            await sync(d)

            # offen: keine Scope-Warnung, beide Hosts auf der Karte (auto)
            nx = (await c.get(f"{base}/next")).json()
            assert nx["scope_warning"] is None, nx["scope_warning"]
            g = (await c.get(f"{base}/graph")).json()
            assert _host(g, PRIV) is not None and _host(g, PUB) is not None
            assert (await _lane(d, PRIV))[0] == "auto"
            assert (await _lane(d, PUB))[0] == "auto"
            st = (await c.get(f"{BASE}/status")).json()
            assert st["project"]["scope_open"] is True

            # Ausschluss wirkt: 8.8.8.8 verschwindet von der Karte
            rc, out = await cli("scope", "exclude", PUB, "--yes")
            assert rc == 0, out
            await sync(d)
            g = (await c.get(f"{base}/graph")).json()
            assert _host(g, PUB) is None and _host(g, PRIV) is not None
            assert (await c.get(f"{base}/scope")).json()["open"] is True
            assert _targets((await c.get(f"{base}/next")).json()) == [PUB]  # Ausschluss: Warnung

            # Einschluss ergänzt den offenen Scope, der bleibt offen
            rc, out = await cli("scope", "add", NET, "--yes")
            assert rc == 0, out
            sc = (await c.get(f"{base}/scope")).json()
            assert sc["open"] is True and sc["include"] == [NET] and sc["exclude"] == [PUB]

            # Schliessen: die Warnung für den öffentlichen Namen kommt wieder
            rc, out = await cli("scope", "close", "--yes")
            assert rc == 0, out
            await sync(d)
            nx = (await c.get(f"{base}/next")).json()
            assert GH in _targets(nx), nx["scope_warning"]
            assert (await c.get(f"{base}/scope")).json()["open"] is False
            assert (await c.get(f"{BASE}/status")).json()["project"]["scope_open"] is False
            rc, out = await cli("scope")
            assert out.splitlines()[0] == "Scope: geschlossen (nur die Einschlüsse)"
            g = (await c.get(f"{base}/graph")).json()
            assert _host(g, PRIV) is not None  # 10.36.198.11 bleibt über den Einschluss

            # Rückgängig öffnet wieder
            rc, out = await cli("scope", "undo", "--yes")
            assert rc == 0, out
            await sync(d)
            assert (await c.get(f"{base}/scope")).json()["open"] is True
            nx = (await c.get(f"{base}/next")).json()
            # github.com wieder im Scope; übrig bleibt nur das ausgeschlossene 8.8.8.8 (nmap-Befehl)
            assert _targets(nx) == [PUB], nx["scope_warning"]

            # eigene Adressen der Kali (E42) und Sonderadressen: nie Host, auch bei offenem Scope (am
            # Ende: die Scope-Warnung nennt den jüngsten Befehl, 127.0.0.1 ist nie implizit im Scope)
            await term.command(f"nmap -sV {KALI_PRIV} {KALI_PUB} 127.0.0.1", _nmap(
                (KALI_PRIV, "22/tcp open  ssh     OpenSSH 9.6"),
                (KALI_PUB, "80/tcp open  http    nginx"),
                ("127.0.0.1", "631/tcp open  ipp     CUPS 2.4")), cwd=ws)
            await term.acked()
            await sync(d)
            g = (await c.get(f"{base}/graph")).json()
            for ip in (KALI_PRIV, KALI_PUB, "127.0.0.1"):
                assert _host(g, ip) is None, ip
                lane = await _lane(d, ip)
                assert lane is None or lane[0] != "auto", (ip, lane)

            assert "127.0.0.1" in _targets((await c.get(f"{base}/next")).json())
            assert KALI_PUB not in _targets((await c.get(f"{base}/next")).json())

            # E133: sehr breite Einträge nach bestätigtem «kein Kundenauftrag» mit broad
            url = f"{base}/scope/changes"
            for entry, broad in (("10.0.0.0/8", True), ("10.20.0.0/16", False), ("2001:db8::/32", True),
                                 ("2001:db8::/48", False), ("10.0.0.0-10.1.0.1", True)):
                r = await c.post(url, json={"op": "add", "entries": [entry], "dry_run": True})
                assert r.status_code == 200, (entry, r.text)
                assert r.json()["broad"] is broad and r.json()["needs_not_customer"] is False, entry
            r = await c.post(url, json={"op": "add", "entries": ["10.0.0.0/8"]})
            assert r.status_code == 201 and r.json()["broad"] is True
            res = await ctl_ok(paths.ctl_sock, "scope.change", action="add", entries=["172.16.0.0/12"],
                               origin="cli", dry_run=True)
            assert res["broad"] is True
        finally:
            await shim.close()

    run_api(paths, operator, body, fixture=False, local_addrs=lambda: (KALI_PRIV, KALI_PUB, "127.0.0.1"))
