"""Befehl ohne Aktion (``ariadne ai``) zeigt die Hilfe mit allen Aktionen statt nur der Fehlerzeile."""

from __future__ import annotations

import pytest

from ariadne.cli.main import build_parser


@pytest.mark.parametrize("argv, actions", [
    (["ai"], ["setup", "status", "check", "allow-cloud", "remove-key"]),
    ([], ["setup", "start", "scope", "ai"]),
])
def test_missing_action_prints_help(capsys, argv, actions):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(argv)
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "arguments are required" not in err
    assert all(a in err for a in actions)


def test_other_errors_unchanged(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["ai", "gibtsnicht"])
    assert exc.value.code == 2
    assert "invalid choice" in capsys.readouterr().err
