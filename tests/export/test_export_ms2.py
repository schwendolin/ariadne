"""Goldener Test des Exports mit dem Fixture MS2 (E62, Architektur 8.7).

Echter Daemon mit Auswertung, das Projekt aus ``tests/e2e/ui_fixture.py`` (nmap gegen
Metasploitable2, msf-Sitzung, Listener, Eingabe ohne Echo, Schlüsselschritte, Finding F1) und ein
feindlicher Befehl. Geprüft werden Aufbau, Inhalt, Manifest, Masken und die Harmlosigkeit des
Markdowns.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from tests.core.fakeshim import ctl_ok
from tests.export.helpers import OWN_SECRET, read_tree, run, unsafe_markdown
from tests.integration.helpers import Term

HOSTILE_CMD = (
    "echo '![x](http://evil.example/t.png) <img src=x> `$= dv.x` [[Geheim]] %%c%% ==h== ‮abc \x1b[31m'"
)


async def _ms2(d: Any, paths: Any) -> dict[str, Any]:
    from tests.e2e.ui_fixture import _fixture_ms2
    from tests.web.api.helpers import sync

    pid, shims = await _fixture_ms2(d, paths)
    ws = Path(d.project.info.workspace)
    # feindlicher Befehl in einem eigenen Terminal (HTML, Bild, Embed, Dataview, Bidi, ESC)
    from tests.core.fakeshim import FakeShim

    s4 = await FakeShim(paths.term_sock).connect(proto=2)
    await s4.wait_state(rec="on")
    t4 = Term(s4)
    await t4.command(
        HOSTILE_CMD, b"![x](http://evil.example/t.png) <script>alert(1)</script>\r\n", cwd=str(ws)
    )
    await t4.acked()
    await sync(d)
    return {"pid": pid, "shims": [*shims, s4], "ws": ws}


def _export(paths: Any, operator: Any, check: Any, **args: Any) -> None:
    async def scenario(d: Any) -> None:
        fx = await _ms2(d, paths)
        try:
            res = await ctl_ok(paths.ctl_sock, "export.run", **args)
            await check(d, fx, res)
        finally:
            for s in fx["shims"]:
                await s.close()

    run(paths, operator, scenario, local_addrs=lambda: ("192.168.56.102",))


def test_export_cys_golden(paths, operator):
    async def check(d: Any, fx: dict[str, Any], res: dict[str, Any]) -> None:
        root = fx["ws"] / res["path"]
        assert res["export_id"].endswith("-cys") and root.is_dir()
        assert oct(root.stat().st_mode & 0o777) == "0o700"
        tree = read_tree(root)
        names = set(tree)
        for fixed in (
            "00 Übersicht.md",
            "01 Angriffspfad.md",
            "02 Writeup.md",
            "03 Findings.md",
            "Credentials.md",
            "Zeitachse.md",
            "_ariadne/manifest.json",
        ):
            assert fixed in names, fixed
        assert any(n.startswith("Hosts/") and n.endswith("-192-168-56-101.md") for n in names)
        assert any(n.startswith("Belege/") and n.endswith("-nmap.md") for n in names)
        # Manifest: SHA-256 jeder Datei, Kettenkopf des Journals und der Belege
        man = json.loads(tree["_ariadne/manifest.json"])
        assert man["format"] == "ariadne-export/1" and man["template"] == "cys"
        assert man["klartext"] is False
        assert isinstance(man["chain"]["seq"], int) and len(man["chain"]["hash"]) == 64
        listed = {f["path"]: f for f in man["files"]}
        assert set(listed) == names - {"_ariadne/manifest.json"}
        for path, f in listed.items():
            assert hashlib.sha256(tree[path]).hexdigest() == f["sha256"]
            assert f["size"] == len(tree[path])
        assert man["evidence"] and all(len(e["chain"]["hash"] or "") == 64 for e in man["evidence"])
        # Inhalte
        text = {n: b.decode("utf-8") for n, b in tree.items() if n.endswith(".md")}
        wu = text["02 Writeup.md"]
        for heading in (
            "Reconnaissance",
            "Scanning und Enumeration",
            "Exploitation",
            "Post-Exploitation",
            "Reporting",
        ):
            assert "## " in wu and heading in wu
        scan = wu.split("Scanning und Enumeration", 1)[1].split("## 3 Exploitation", 1)[0]
        assert "nmap \\-sV \\-sC" in scan or "nmap -sV -sC -oA scans/ms2 192.168.56.101" in scan
        expl = wu.split("## 3 Exploitation", 1)[1].split("## 4 Post", 1)[0]
        assert "msfconsole" in expl and "nc -lvnp 4445" in expl
        fnd = text["03 Findings.md"]
        assert "F1 vsftpd 2.3.4 Backdoor" in fnd.replace("\\", "")
        assert "Kritisch (Critical)" in fnd
        assert "T1190 (belegt)" in fnd.replace("\\", "") or "T1190 (Hypothese)" in fnd.replace("\\", "")
        assert "CVE\\-2011\\-2523 (Hypothese)" in fnd
        assert "vsftpd aktualisieren" in fnd
        path = text["01 Angriffspfad.md"]
        assert "Schritt 1: Foothold" in path and "Schritt 2: Loot" in path
        host = next(v for k, v in text.items() if k.startswith("Hosts/") and "192-168-56-101" in k)
        assert "vsftpd" in host and "2\\.3\\.4" not in host and "2.3.4" in host
        assert host.count("\n| ") >= 23
        ov = text["00 Übersicht.md"]
        assert "Hosts im Scope: 1" in ov and "192.168.56.0/24" in ov
        beleg = next(v for k, v in text.items() if k.startswith("Belege/") and k.endswith("-nmap.md"))
        assert "Kettenkopf: Event" in beleg and "Terminal: T1 scan" in beleg
        assert "21/tcp" in beleg and "Zeilennummern" in beleg
        import re

        assert re.search(r"Zeit: \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", beleg)
        # Sicherheit: eigenes Secret nie, Eingabe ohne Echo nie, feindliches Markdown entschärft
        for n, b in tree.items():
            assert OWN_SECRET.encode() not in b, n
            assert b"geheim-731" not in b, n
        for n, md in text.items():
            assert unsafe_markdown(md) == [], (n, unsafe_markdown(md)[:3])
        tl = text["Zeitachse.md"]
        assert "\\<ESC\\>" in tl and "\\<U+202E\\>" in tl
        assert "\\!\\[x\\]" in tl and "http\\[\\:\\]//evil" in tl
        # Liste
        lst = await ctl_ok(paths.ctl_sock, "export.list")
        assert lst["exports"][0]["export_id"] == res["export_id"]
        assert lst["running"] is None

    _export(paths, operator, check, template="cys")


def test_export_htb_and_klartext_policy(paths, operator):
    async def check(d: Any, fx: dict[str, Any], res: dict[str, Any]) -> None:
        root = fx["ws"] / res["path"]
        wu = (root / "02 Writeup.md").read_text("utf-8")
        for heading in (
            "Enumeration",
            "Foothold",
            "Privilege Escalation",
            "Pivot",
            "Loot",
            "Lessons Learned",
        ):
            assert heading in wu
        # Klartext ohne Bestätigung: abgelehnt
        from tests.core.fakeshim import ctl as ctl_call

        bad = await ctl_call(paths.ctl_sock, "export.run", template="htb", klartext=True)
        assert bad["ok"] is False and bad["error"]["code"] == "policy"
        good = await ctl_ok(paths.ctl_sock, "export.run", template="htb", klartext=True, confirm="KLARTEXT")
        man = json.loads((fx["ws"] / good["path"] / "_ariadne" / "manifest.json").read_text("utf-8"))
        assert man["klartext"] is True and "klartext" in man["warnings"]
        for p in (fx["ws"] / good["path"]).rglob("*"):
            if p.is_file():
                assert OWN_SECRET.encode() not in p.read_bytes()

    _export(paths, operator, check, template="htb")
