"""Golden-Tests der Denkanstösse mit den Lab-Fixtures (Vertrag v0.1-Oberfläche 4.3).

* MS2 mit ``nmap -sV -sC`` (Text und XML, wie ``tests/projection/test_ausw_golden.py::_ms2``),
* MS2 nur mit ``nmap -sV`` (der Fall aus dem Design, Ariadne_Runde_1 1a: D1 R-ANON-ZUGRIFF auf .101:21
  mit «Beleg: nmap -sV · Zeile 6» (Uhrzeit in ``ts``) und ``nmap -p 21 --script ftp-anon 192.168.56.101``),
* Lame mit ``nmap -sV -sC``,
* ein Host mit feindlichen Bannern: keine fertige Vorlage, nur Einzelwerte.

``python -m pytest tests/rules --update-golden`` (oder ``ARIADNE_UPDATE_GOLDEN=1``) schreibt
``tests/golden/rules/*.json`` neu. Die Kurzform (Regel, Titel, Befehle) steht zusätzlich hier im Test.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import time
from pathlib import Path

import pytest

from ariadne.rules.engine import SUSPECT_REASONS
from ariadne.rules.templates import TEMPLATES, skeleton
from tests.projection import helpers as projection_helpers
from tests.rules import helpers as H
from tests.rules.test_templates import SHELLS, shell_argv

GOLDEN = Path(__file__).parents[1] / "golden" / "rules"
CASES = {
    "ms2_sv_sc": lambda: H.ms2(),
    "ms2_sv": lambda: H.ms2(scripts=False),
    "lame_sv_sc": H.lame,
    "hostile": H.hostile,
}
SUGGESTION_KEYS = {
    "suggestion_key",
    "origin",
    "rule_id",
    "goal_id",
    "kind",
    "title",
    "ctrl",
    "title_parts",
    "host_id",
    "service_id",
    "host_label",
    "reason",
    "ctrl_reason",
    "evidence",
    "stages",
    "templates",
    "items",
    "state",
    "decision_id",
    "basis",
    "flags",
    "ts",
    "ai",
}
TEMPLATE_KEYS = {"template_id", "tool", "label", "rendered", "command", "parts", "values", "blocked_reason"}
VALUE_KEYS = {"slot", "type", "label", "value", "ctrl", "target", "safe"}
ITEM_KEYS = {"service_id", "port", "proto", "label", "ctrl", "label_parts", "template"}
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]")

U = "192.168.56.101"
NMAP_ANON_21 = f"nmap -p 21 --script ftp-anon {U}"

MS2_SV_SC = [
    (
        "R-VERSION-RECHERCHE",
        f"Versionen recherchieren: {U} (8 Dienste)",
        [
            "searchsploit vsftpd 2.3.4",
            "searchsploit OpenSSH 4.7p1",
            "searchsploit ISC BIND 9.4.2",
            "searchsploit Apache 2.2.8",
            "searchsploit Samba 3.0.20",
            "searchsploit ProFTPD 1.3.1",
            "searchsploit MySQL 5.0.51a",
            "searchsploit Apache Tomcat Coyote JSP 1.1",
        ],
    ),
    (
        "R-SMB-SHARES",
        f"SMB-Shares auf {U} auflisten",
        [f"smbclient -N -L //{U}", f"smbmap -H {U}", f"nmap -p 445 --script smb-enum-shares {U}"],
    ),
    (
        "R-NFS-EXPORTS",
        f"NFS-Exporte von {U} auflisten",
        [f"showmount -e {U}", f"nmap -p 111 --script nfs-showmount {U}"],
    ),
    (
        "R-WEB-INHALT",
        f"Webinhalt auf {U}:80 untersuchen",
        [
            f"curl -i http://{U}:80/",
            f"whatweb http://{U}:80/",
            f"gobuster dir -u http://{U}:80/ -w /usr/share/wordlists/dirb/common.txt",
            f"nikto -h http://{U}:80/",
        ],
    ),
    (
        "R-WEB-INHALT",
        f"Webinhalt auf {U}:8180 untersuchen",
        [
            f"curl -i http://{U}:8180/",
            f"whatweb http://{U}:8180/",
            f"gobuster dir -u http://{U}:8180/ -w /usr/share/wordlists/dirb/common.txt",
            f"nikto -h http://{U}:8180/",
        ],
    ),
    ("R-STANDARD-CREDS", f"Gibt es auf {U}:23 Standardkonten?", [f"telnet {U} 23"]),
    ("R-STANDARD-CREDS", f"Gibt es auf {U}:5900 Standardkonten?", [f"vncviewer {U}::5900"]),
    (
        "R-STANDARD-CREDS",
        f"Gibt es auf {U}:8180 Standardkonten?",
        [f"nmap -p 8180 --script http-default-accounts {U}"],
    ),
    (
        "R-DB-ZUGRIFF",
        f"Lässt die Datenbank auf {U}:3306 eine Anmeldung zu?",
        [f"mysql -h {U} -P 3306 -u root --skip-ssl", f"nmap -p 3306 --script mysql-empty-password {U}"],
    ),
    (
        "R-DB-ZUGRIFF",
        f"Lässt die Datenbank auf {U}:5432 eine Anmeldung zu?",
        [f"psql -h {U} -p 5432 -U postgres"],
    ),
    (
        "R-SMTP-USER",
        f"Lassen sich über SMTP auf {U}:25 Benutzer ermitteln?",
        [
            f"smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t {U} -p 25",
            f"nmap -p 25 --script smtp-enum-users {U}",
        ],
    ),
    ("R-FULL-PORTSCAN", f"Alle TCP-Ports von {U} scannen", [f"nmap -p- -T4 {U}"]),
    ("R-UDP-SCAN", f"UDP-Ports von {U} scannen", [f"sudo nmap -sU --top-ports 100 {U}"]),
]

L = "10.10.10.3"
LAME = [
    (
        "R-VERSION-RECHERCHE",
        f"Versionen recherchieren: {L} (3 Dienste)",
        ["searchsploit vsftpd 2.3.4", "searchsploit OpenSSH 4.7p1", "searchsploit Samba 3.0.20"],
    ),
    (
        "R-SMB-SHARES",
        f"SMB-Shares auf {L} auflisten",
        [f"smbclient -N -L //{L}", f"smbmap -H {L}", f"nmap -p 445 --script smb-enum-shares {L}"],
    ),
    ("R-FULL-PORTSCAN", f"Alle TCP-Ports von {L} scannen", [f"nmap -p- -T4 {L}"]),
    ("R-UDP-SCAN", f"UDP-Ports von {L} scannen", [f"sudo nmap -sU --top-ports 100 {L}"]),
]


def _all() -> dict[str, list[dict]]:
    out = {}
    for name, build in CASES.items():
        conn, _p = build()
        out[name] = H.suggestions(conn, state="all")
    return out


@pytest.fixture(scope="module")
def results() -> dict[str, list[dict]]:
    old = os.environ.get("TZ")
    os.environ["TZ"] = "CET-1CEST,M3.5.0,M10.5.0/3"
    time.tzset()
    try:
        res = _all()
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()
    while projection_helpers.OPEN:
        projection_helpers.OPEN.pop().close()
    return res


@pytest.mark.parametrize("name", sorted(CASES))
def test_golden_file(name, results, update_golden):
    got = results[name]
    path = GOLDEN / f"{name}.json"
    text = json.dumps(got, ensure_ascii=False, indent=1, sort_keys=True) + "\n"
    if update_golden:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.exists(), f"{path} fehlt: python -m pytest tests/rules --update-golden"
    assert json.loads(path.read_text(encoding="utf-8")) == got


def test_ms2_with_scripts(results):
    """-sC hat ftp-anon (21 erlaubt, 2121 ohne Ausgabe) und die SMB-Skripte schon ausgeführt: kein
    R-ANON-ZUGRIFF; Samba-Version aus smb-os-discovery; Kali (eigene Adresse) taucht nie auf."""
    assert H.summary(results["ms2_sv_sc"]) == MS2_SV_SC
    assert not any(H.KALI in json.dumps(s) for s in results["ms2_sv_sc"])


def test_lame(results):
    assert H.summary(results["lame_sv_sc"]) == LAME


def test_ms2_without_scripts_matches_design(results):
    items = results["ms2_sv"]
    first = items[0]
    assert (
        first["rule_id"] == "R-ANON-ZUGRIFF"
        and first["goal_id"] == "PZ-AUTH-ANON"
        and first["kind"] == "goal"
    )
    assert first["title"] == f"Unauthentisierten Zugriff auf {U}:21 prüfen"
    assert first["title_parts"] == [
        {"text": "Unauthentisierten Zugriff auf ", "target": False},
        {"text": f"{U}:21", "target": True},
        {"text": " prüfen", "target": False},
    ]
    assert first["reason"] == "FTP-Dienst ohne geprüfte anonyme Anmeldung"
    assert [e["label"] for e in first["evidence"]] == ["nmap -sV · Zeile 6"]
    # die Uhrzeit steht in ts (UTC); die Oberfläche zeigt «nmap -sV · 14:02 · Zeile 6» in Lokalzeit
    assert [e["ts"] for e in first["evidence"]] == ["2026-10-08T12:02:11.000000Z"]
    assert first["evidence"][0]["lines"] == [5, 5] and first["evidence"][0]["unit_id"] == "cmd1"
    assert first["stages"] == {
        "question": "Welche Daten gibt dieser Dienst ohne Anmeldung preis?",
        "direction": "Viele vsftpd-Installationen erlauben Gast- oder anonyme Logins.",
    }
    tpl = first["templates"][0]
    assert tpl["command"] == NMAP_ANON_21 and tpl["label"] == "nmap-Skript ftp-anon"
    assert tpl["parts"] == [
        {"text": "nmap -p ", "target": False},
        {"text": "21", "target": True},
        {"text": " --script ftp-anon ", "target": False},
        {"text": U, "target": True},
    ]
    # E119: ein Denkanstoss pro Host, aufgeklappt die Liste mit je einer Vorlage
    (d2,) = H.by_rule(items, "R-VERSION-RECHERCHE")
    assert d2["title"] == f"Versionen recherchieren: {U} (7 Dienste)"
    assert d2["title_parts"] == [
        {"text": "Versionen recherchieren: ", "target": False},
        {"text": U, "target": True},
        {"text": " (7 Dienste)", "target": False},
    ]
    assert d2["service_id"] is None and d2["host_id"] == f"ip:default/{U}"
    assert d2["reason"] == "Produkt und Version für 7 Dienste bekannt"
    first_item = d2["items"][0]
    assert first_item["service_id"] == f"svc:ip:default/{U}|tcp/21"
    assert (first_item["port"], first_item["proto"]) == (21, "tcp")
    assert first_item["label"] == "vsftpd 2.3.4 · 21/tcp"
    assert first_item["label_parts"] == [
        {"text": "vsftpd 2.3.4", "target": True},
        {"text": " · 21/tcp", "target": False},
    ]
    assert first_item["template"]["command"] == "searchsploit vsftpd 2.3.4"
    assert [i["port"] for i in d2["items"]] == [21, 22, 53, 80, 2121, 3306, 8180]
    # ältere Ansichten: die ersten vier Vorlagen auch in ``templates``
    assert d2["templates"] == [i["template"] for i in d2["items"][:4]]
    anon = [(s["title"], s["service_id"]) for s in H.by_rule(items, "R-ANON-ZUGRIFF")]
    assert anon == [
        (f"Unauthentisierten Zugriff auf {U}:21 prüfen", f"svc:ip:default/{U}|tcp/21"),
        (f"Unauthentisierten Zugriff auf {U}:445 prüfen", f"svc:ip:default/{U}|tcp/445"),
        (f"Unauthentisierten Zugriff auf {U}:2121 prüfen", f"svc:ip:default/{U}|tcp/2121"),
    ]
    # ohne -sC und ohne smb-os-discovery bleibt die Samba-Version ein Bereich: keine Recherche
    assert not any("Samba" in i["label"] for i in d2["items"])


def test_hostile_products_give_no_template_only_values(results):
    items = results["hostile"]
    (version,) = H.by_rule(items, "R-VERSION-RECHERCHE")  # E119: ein Denkanstoss für den Host
    assert len(version["items"]) == len(H.HOSTILE_PRODUCTS)
    assert version["title"] == f"Versionen recherchieren: {H.HOSTILE} ({len(H.HOSTILE_PRODUCTS)} Dienste)"
    suspect = any(i["template"]["blocked_reason"] in SUSPECT_REASONS for i in version["items"])
    assert suspect and "injection_suspect" in version["flags"]
    reasons = {}
    for it in version["items"]:
        tpl = it["template"]
        assert not tpl["rendered"] and tpl["command"] is None and tpl["parts"] == []
        assert [v["label"] for v in tpl["values"]] == ["Werkzeug", "Produkt", "Version"]
        assert tpl["values"][0]["value"] == "searchsploit" and tpl["values"][1]["safe"] is False
        reasons[str(it["port"])] = tpl["blocked_reason"]
    assert reasons == {
        "21": "shell_meta",
        "2121": "shell_meta",
        "80": "shell_meta",
        "3306": "newline",
        "8080": "control",
        "8180": "control",
        "10021": "non_ascii",
    }
    shown = {str(i["port"]): i["template"]["values"][1]["value"] for i in version["items"]}
    assert shown["3306"] == "MySQL<LF>INJECTED" and shown["8080"] == "nginx<ESC>[2J"
    assert shown["8180"] == "Apache Tomcat<U+202E>/Coyote"  # nicht druckbar: unverändert, sichtbar gemacht
    assert shown["21"] == "vsftpd'; !sh -c 'id"
    ctrl = {str(i["port"]): i["ctrl"] for i in version["items"]}
    assert ctrl["3306"] is True and ctrl["21"] is False
    assert version["ctrl"] is False  # der Titel nennt nur die Adresse
    # Vorlagen ohne Produkt (nur IP und Port) bleiben fertig; die Richtung nennt kein feindliches Produkt
    anon = {s["service_id"].rsplit("/", 1)[1]: s for s in H.by_rule(items, "R-ANON-ZUGRIFF")}
    assert anon["21"]["templates"][0]["command"] == f"nmap -p 21 --script ftp-anon {H.HOSTILE}"
    assert anon["21"]["stages"]["direction"] == "Viele FTP-Server erlauben Gast- oder anonyme Logins."
    assert anon["10021"]["stages"]["direction"] == "Viele FTP-Server erlauben Gast- oder anonyme Logins."


@pytest.mark.parametrize("name", sorted(CASES))
def test_shape_matches_web_api_18_6(name, results):
    keys = set()
    for s in results[name]:
        assert set(s) == SUGGESTION_KEYS
        assert re.fullmatch(r"sg:[0-9a-f]{24}", s["suggestion_key"]) and s["suggestion_key"] not in keys
        keys.add(s["suggestion_key"])
        assert re.fullmatch(r"[0-9a-f]{16}", s["basis"])
        assert (
            s["origin"] == "rule"
            and s["ai"] is None
            and s["kind"] in ("goal", "question", "hypothesis", "hint")
        )
        assert s["state"] == "open" and s["decision_id"] is None
        assert s["title"] == "".join(p["text"] for p in s["title_parts"])
        assert 1 <= len(s["evidence"]) <= 5 and len(s["templates"]) <= 4
        assert set(s["stages"]) == {"question", "direction"} and all(s["stages"].values())
        assert set(s["flags"]) <= {"from_target", "injection_suspect"} and s["flags"] == sorted(s["flags"])
        assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", s["ts"])
        for e in s["evidence"]:
            assert set(e) == {"claim_key", "unit_id", "lines", "label", "ts"} and re.fullmatch(
                r"[0-9a-f]{64}", e["claim_key"]
            )
        assert isinstance(s["items"], list) and len(s["items"]) <= 64
        assert bool(s["items"]) is (s["rule_id"] == "R-VERSION-RECHERCHE")
        for it in s["items"]:
            assert set(it) == ITEM_KEYS and it["label"] == "".join(p["text"] for p in it["label_parts"])
            assert it["service_id"].endswith(f"|{it['proto']}/{it['port']}")
        if s["items"]:
            assert s["templates"] == [i["template"] for i in s["items"][:4]]
        for t in [*s["templates"], *(i["template"] for i in s["items"])]:
            assert set(t) == TEMPLATE_KEYS and t["template_id"] in TEMPLATES
            assert all(set(v) == VALUE_KEYS for v in t["values"])
            if t["rendered"]:
                assert t["command"] == "".join(p["text"] for p in t["parts"])
                assert t["blocked_reason"] is None and all(v["safe"] for v in t["values"])
        text = json.dumps(s, ensure_ascii=False)
        assert not _CTRL.search(json.loads(json.dumps(text))), s["suggestion_key"]  # alles sichtbar
        assert "\u2022" not in text  # keine maskierten Secrets in diesen Fällen


def _expected_argv(tpl: dict) -> list[str]:
    text = TEMPLATES[tpl["template_id"]].text
    if text.startswith("nmap ") and " -6 " in tpl["command"]:
        text = TEMPLATES[tpl["template_id"]].text6 or text
    tokens, slots = skeleton(text)
    vals = {v["slot"]: str(v["value"]) for v in tpl["values"]}
    out: list[str] = []
    for tok in tokens:
        m = re.fullmatch(r"QQSLOT(\d+)QQ", tok)
        if m and slots[int(m.group(1))] == "service.product":
            out.extend(vals["service.product"].split(" "))
            continue
        out.append(re.sub(r"QQSLOT(\d+)QQ", lambda mm: vals[slots[int(mm.group(1))]], tok))
    return out


@pytest.mark.parametrize("shell", SHELLS)
def test_every_rendered_golden_command_splits_exactly(results, shell):
    """Jede gerenderte Vorlage aller Golden-Fälle zerfällt mit shlex und in echten Shells in genau die
    erwarteten Wörter (Werkzeug, fester Text, Einzelwerte)."""
    seen = 0
    for items in results.values():
        for s in items:
            for t in [*s["templates"], *(i["template"] for i in s["items"])]:
                if not t["rendered"]:
                    continue
                expected = _expected_argv(t)
                assert shlex.split(t["command"]) == expected
                assert shell_argv(shell, t["command"]) == expected
                seen += 1
    assert seen > 50
