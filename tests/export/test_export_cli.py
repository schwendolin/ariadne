"""``ariadne export``: Klartext nur mit Bestätigung im Terminal, Warnungen, Ausgabe nur über term_safe."""

from __future__ import annotations

import io
from typing import Any

import pytest

from ariadne.cli import export as cli_export
from ariadne.cli.common import CliError
from ariadne.cli.main import build_parser


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def _args(*argv: str) -> Any:
    return build_parser().parse_args(["export", *argv])


def test_export_prints_path_and_warnings(monkeypatch, capsys):
    calls: list[dict[str, Any]] = []

    def fake(paths: Any, payload: dict[str, Any]) -> dict[str, Any]:
        calls.append(payload)
        return {"path": "exports/20261018T101500Z-cys", "files": 12, "warnings": ["sync_folder", "x\x1b[31m"]}

    monkeypatch.setattr(cli_export, "_client_call", fake)
    assert cli_export.cmd_export(None, _args()) == 0  # type: ignore[arg-type]
    out = capsys.readouterr().out
    assert calls == [{"template": "cys"}]
    assert "exports/20261018T101500Z-cys" in out and "Sync-Ordner" in out
    assert "\x1b" not in out and "<ESC>" in out


def test_klartext_needs_terminal_confirmation(monkeypatch):
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(cli_export, "_client_call", lambda p, payload: sent.append(payload) or {"path": "e"})
    monkeypatch.setattr("sys.stdin", io.StringIO("KLARTEXT\n"))
    with pytest.raises(CliError):
        cli_export.cmd_export(None, _args("--klartext"))  # type: ignore[arg-type]
    monkeypatch.setattr("sys.stdin", _Tty("nein\n"))
    with pytest.raises(CliError):
        cli_export.cmd_export(None, _args("--klartext", "--template", "htb"))  # type: ignore[arg-type]
    assert sent == []
    monkeypatch.setattr("sys.stdin", _Tty("KLARTEXT\n"))
    assert cli_export.cmd_export(None, _args("--klartext", "--template", "htb")) == 0  # type: ignore[arg-type]
    assert sent == [{"template": "htb", "klartext": True, "confirm": "KLARTEXT"}]
