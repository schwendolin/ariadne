"""Textansichten der CLI: Zieldaten gehen nur über ``term_safe`` ins Terminal."""

from __future__ import annotations

import re

from ariadne.cli.views import render_reparse, render_search, render_view

EVIL = "\x1b]2;owned\x07\x1b[31mvsftpd‮\r\nPRMT> rm -rf /"
CTRL = re.compile(r"[\x00-\x1f\x7f\x80-\x9f‮]")


def _check(lines: list[str]) -> str:
    text = "\n".join(lines)
    for line in lines:
        assert not CTRL.search(line), repr(line)
    return text


def test_hostile_values_are_escaped():
    svc = {"port": 21, "proto": "tcp", "name": EVIL, "product": EVIL, "version": EVIL, "state": "open",
           "claim_state": "candidate", "cves": [EVIL], "host": EVIL}
    hosts = [{"label": EVIL, "claim_state": "candidate", "scope": "in", "knowledge": EVIL, "access": "none",
              "work": "open", "progress": 3, "os": EVIL, "names": [EVIL], "services": [svc], "conflicts": 1}]
    text = _check(render_view("hosts", hosts))
    assert "<ESC>" in text and "(Nebel)" in text
    _check(render_view("services", [svc]))
    inbox = [{"ref": "g12345678", "kind": "candidate_group", "title": EVIL, "ts": 1, "summary": {"hosts": 1},
              "items": [{"kind": "candidate_group", "ref": "abc", "subject": EVIL,
                         "predicate": "service.product", "value": EVIL, "confidence": "high", "scope": "in",
                         "suspect": True}]},
             {"ref": "g87654321", "kind": "ctx_suggestion", "title": "Kontext klären", "ts": 2,
              "items": [{"kind": "ctx_suggestion", "payload": {"terminal_id": EVIL, "reason": EVIL,
                                                               "candidate": EVIL}}]}]
    text = _check(render_view("inbox", inbox))
    assert "ariadne confirm g12345678" in text and "Injection-Verdacht" in text
    tl = [{"type": "command", "title": EVIL, "context": EVIL, "ts": 1, "exit": 0, "src_ip": EVIL,
           "scope": ["out"], "flags": ["gap", EVIL]},
          {"type": "segment", "context": "10.10.10.3 [revshell]", "lines": 4, "ts": 2},
          {"type": "keystep", "title": "foothold", "context": EVIL, "note": EVIL, "ts": 3}]
    text = _check(render_view("timeline", tl))
    assert "Ziel ausserhalb Scope oder unbekannt" in text
    _check(render_view("keysteps", [{"ordinal": 1, "step": "foothold", "host": EVIL, "note": EVIL, "ts": 1}]))
    _check(render_view("pending", [{"path": EVIL, "reason": "symlink", "ts": 1}]))
    _check(render_search([{"ts": 1, "context": EVIL, "text": EVIL}]))
    _check(render_reparse({"orphans": [{"kind": EVIL, "seq": 3, "reason": EVIL}],
                           "added_sample": [{"subject": EVIL, "predicate": EVIL, "value": EVIL}]}))


def test_empty_views():
    for what in ("hosts", "services", "inbox", "timeline", "keysteps", "pending"):
        assert render_view(what, [])
    assert render_search([]) == ["Keine Treffer."]
    assert "Verwaiste Entscheide: keine" in render_reparse({})[-1]
