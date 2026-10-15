"""CLI-Befehle der Auswertung ohne Daemon: ``undo``, ``confirm`` und ``show inbox`` mit
den Antworten aus dem Vertrag (5.2); der Daemon-Aufruf ist ersetzt."""

from __future__ import annotations

import argparse
from typing import Any

import pytest

from ariadne.cli import analysis


def _parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ariadne")
    analysis.register(ap.add_subparsers(dest="cmd"))
    return ap


@pytest.fixture
def calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any]]]:
    seen: list[tuple[str, dict[str, Any]]] = []
    answers = {
        "unit.distrust": {"cmd_id": "0199a2b3-0000@1234", "cmd_ref": "0199a2b3@1234", "rejected": 21,
                          "weakened": 2},
        "claim.confirm": {"confirmed": 5, "claims": [], "group": True,
                          "excluded": {"own_address": 1, "out_of_scope": 3}, "excluded_sample": []},
        "show": {"what": "inbox", "items": [], "quiet": {"system_accounts": 27, "out_of_scope": 3},
                 "ingest": {"last_error": None}},
    }

    def fake(paths: Any, op: str, **args: Any) -> Any:
        seen.append((op, args))
        return answers[op]

    monkeypatch.setattr(analysis, "_call", fake)
    return seen


def test_undo_command(calls, capsys):
    args = _parser().parse_args(["undo", "0199a2b3@1234", "--reason", "falsches Ziel"])
    assert args.fn(None, args) == 0
    assert calls == [("unit.distrust", {"ref": "0199a2b3@1234", "reason": "falsches Ziel"})]
    out = capsys.readouterr().out
    assert "Befehl 0199a2b3@1234 rückgängig gemacht: 21 Werte verworfen, 2 weitere" in out


def test_confirm_reports_exclusions(calls, capsys):
    args = _parser().parse_args(["confirm", "g1a2b3c4d"])
    assert args.fn(None, args) == 0
    out = capsys.readouterr().out
    assert "5 Claim(s) bestätigt." in out
    assert ("Nicht übernommen: 1 eigene Adresse (Kali), 3 ausserhalb des Scopes; einzeln: "
            "ariadne confirm <claim>") in out


def test_show_inbox_with_quiet_sum(calls, capsys):
    args = _parser().parse_args(["show", "inbox"])
    assert args.fn(None, args) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "Still (nie zum Klären): +27 Systemkonten, 3 Werte ausserhalb des Scopes"
    assert out[1] == "Inbox leer."
