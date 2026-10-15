"""CLI-Ansichten der Drei-Spuren-Regel: auto, stille Zähler, Bestätigen mit Ausschlüssen,
Rückgängig; alle Werte nur über ``term_safe`` (feindliche Werte wie in test_cli_views)."""

from __future__ import annotations

import re

from ariadne.cli.views import quiet_text, render_confirm, render_undo, render_view

EVIL = "\x1b]2;owned\x07\x1b[31mvsftpd‮\r\nPRMT> rm -rf /"
CTRL = re.compile(r"[\x00-\x1f\x7f\x80-\x9f‮]")


def _check(lines: list[str]) -> str:
    for line in lines:
        assert not CTRL.search(line), repr(line)
    return "\n".join(lines)


def test_hosts_show_auto_and_quiet_counters():
    svc = {"port": 21, "proto": "tcp", "name": "ftp", "product": EVIL, "version": "2.3.4", "state": "open",
           "claim_state": "auto", "cves": []}
    host = {"label": EVIL, "claim_state": "auto", "scope": "in", "knowledge": "versions", "access": "none",
            "work": "open", "progress": 3, "services": [svc],
            "quiet": {"heuristic": 0, "out_of_scope": 3, "mentions": 1, "system_accounts": 27}}
    text = _check(render_view("hosts", [host]))
    assert "[auto, in Scope]" in text and "(auto)" in text and "(Nebel)" not in text
    assert "still: +27 Systemkonten, 3 Werte ausserhalb des Scopes, 1 Erwähnung" in text


def test_inbox_shows_quiet_sum_and_decide_values():
    groups = [{"ref": "g12345678", "kind": "decide_value", "title": EVIL, "ts": 1, "summary": {"hosts": 1},
               "items": [{"kind": "decide_value", "ref": "abc", "subject": EVIL, "predicate": "host.os",
                          "value": EVIL, "confidence": "medium", "scope": "in", "reason": "ai"},
                         {"kind": "decide_value", "ref": "def", "subject": EVIL, "predicate": "host.os",
                          "value": EVIL, "confidence": "high", "scope": "in", "reason": "suspect",
                          "suspect": True}]}]
    text = _check(render_view("inbox", groups, quiet={"system_accounts": 27, "out_of_scope": 3}))
    assert text.splitlines()[0] == "Still (nie zum Klären): +27 Systemkonten, 3 Werte ausserhalb des Scopes"
    assert "KI-Wert" in text and "verdächtige Quelle" in text
    assert "sichere Werte bestätigen: ariadne confirm g12345678" in text
    assert render_view("inbox", [], quiet={"mentions": 0}) == ["Inbox leer."]
    assert quiet_text({"heuristic": 2, "own_address": 1}) == "2 heuristische Werte, 1 eigene Adresse (Kali)"
    one = quiet_text({"system_accounts": 1, "out_of_scope": 1})
    assert one == "+1 Systemkonto, 1 Wert ausserhalb des Scopes"


def test_timeline_names_adopted_values_and_undo_ref():
    tl = [{"type": "command", "title": "nmap -sV 10.10.10.3", "context": "Kali", "ts": 1_790_000_000 * 10**9,
           "cmd_ref": "0199a2b3@1234", "adopted": 21, "distrusted": False},
          {"type": "command", "title": EVIL, "context": "Kali", "ts": 2, "cmd_ref": EVIL, "adopted": 1},
          {"type": "command", "title": "nmap -p- x", "context": "Kali", "ts": 3, "cmd_ref": "0199a2b3@9",
           "adopted": 0, "distrusted": True},
          {"type": "command", "title": "id", "context": "Kali", "ts": 4, "cmd_ref": "x@1", "adopted": 0}]
    text = _check(render_view("timeline", tl))
    assert re.search(r"nmap \d\d:\d\d: 21 Werte übernommen \(ariadne undo 0199a2b3@1234\)", text)
    assert "1 Wert übernommen" in text and "rückgängig gemacht (Befehl 0199a2b3@9)" in text
    assert "ariadne undo x@1" not in text  # ohne übernommene Werte kein Hinweis


def test_confirm_reports_what_was_left_out():
    res = {"confirmed": 2, "group": True,
           "claims": [{"subject": EVIL, "predicate": "host.state", "value": EVIL, "state": "confirmed"}],
           "excluded": {"own_address": 1, "out_of_scope": 3, "ai": 0, "low_confidence": 2, "conflict": 0,
                        "context": 0, "merge": 0, "suspect": 1},
           "excluded_sample": [{"subject": "192.168.56.102", "predicate": "host.address", "value": EVIL,
                                "reason": "own_address"}]}
    text = _check(render_confirm(res))
    assert ("Nicht übernommen: 1 eigene Adresse (Kali), 3 ausserhalb des Scopes, 2 mit niedriger "
            "Konfidenz, 1 mit verdächtiger Quelle; einzeln: ariadne confirm <claim>") in text
    single = render_confirm({"confirmed": 0, "group": False, "excluded": {"own_address": 1}})
    assert single[-1] == "Nicht übernommen: 1 eigene Adresse (Kali)"
    assert render_confirm({"confirmed": 1}) == ["1 Claim(s) bestätigt."]


def test_undo_message():
    text = _check(render_undo({"cmd_id": EVIL, "cmd_ref": EVIL, "rejected": 21, "weakened": 3}))
    assert "21 Werte verworfen, 3 weitere verlieren diese Quelle." in text
