"""``ariadne scope`` und der Hinweis von ``ariadne start <vorhandenes Projekt> --target`` (E129).
Der Daemon ist durch eine Liste der ctl-Aufrufe ersetzt; die Rückfrage ``[j/N]`` zeigt den genauen
Eintrag, ohne Bestätigung wird nichts geschrieben."""

from __future__ import annotations

from typing import Any

import pytest

from ariadne.cli import main as main_mod
from ariadne.cli import scope as scope_cli
from ariadne.cli.main import main
from ariadne.daemon.client import CtlError
from ariadne.project.guardrails import LabAllowlist
from ariadne.scope.change import plan_change

NET = "10.36.198.0/24"
NAME = "recovery.vantis.htb"


class FakeDaemon:
    def __init__(self) -> None:
        self.include = [NET]
        self.exclude: list[str] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.history: list[dict[str, Any]] = []

    def call(self, paths: Any, op: str, *, start: bool = True, **args: Any) -> Any:
        self.calls.append((op, args))
        if op == "scope.show":
            return {"slug": "vantis", "profile": "lab", "version": 1 + len(self.history),
                    "include": list(self.include), "exclude": list(self.exclude),
                    "windows": [], "not_customer": False, "history": list(self.history),
                    "project_id": "p1"}
        if op == "scope.change":
            settings = {"scope": {"include": self.include, "exclude": self.exclude, "windows": []}}
            if args["action"] == "revert":
                plan = {"include": [NET], "exclude": [], "include_removed": [NAME], "op": "revert",
                        "verdicts": {}, "outside": []}
            else:
                try:
                    allow = LabAllowlist.default()
                    plan = plan_change(settings, args["action"], args["entries"], allow).view()
                except ValueError as exc:
                    raise CtlError("conflict", str(exc)) from None
            res = {**plan, "version": 2, "needs_not_customer": bool(plan["outside"]), "decision_id": None}
            if args.get("dry_run"):
                return res
            self.include, self.exclude = plan["include"], plan["exclude"]
            self.history.insert(0, {"decision_id": "dec-1", "version": 2, "op": args["action"],
                                    "entries": args.get("entries", []), "origin": "cli", "ts_utc_ns": 0})
            return {**res, "decision_id": "dec-1"}
        raise AssertionError(op)


@pytest.fixture
def fake(monkeypatch, tmp_path):
    for k in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(k, str(tmp_path / k.lower()))
    f = FakeDaemon()
    monkeypatch.setattr(scope_cli, "_call", f.call)
    return f


def _tty(monkeypatch, answer: str) -> list[str]:
    asked: list[str] = []
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def ask(prompt: str) -> str:
        asked.append(prompt)
        return answer

    monkeypatch.setattr("builtins.input", ask)
    return asked


def test_show_lists_include_exclude_windows(fake, capsys):
    assert main(["scope"]) == 0
    out = capsys.readouterr().out
    assert "Einschlüsse:\n  10.36.198.0/24" in out and "Ausschlüsse:\n  (keine)" in out
    assert "Zeitfenster:\n  (keine: gilt jederzeit)" in out
    assert main(["scope", "show"]) == 0


def test_add_asks_with_exact_entry_and_writes_on_yes(fake, capsys, monkeypatch):
    asked = _tty(monkeypatch, "j")
    assert main(["scope", "add", "Recovery.Vantis.Htb."]) == 0
    out = capsys.readouterr().out
    assert f"Neu im Scope: {NAME}" in out and asked == ["Übernehmen? [j/N] "]
    assert [c[1].get("dry_run", False) for c in fake.calls] == [True, False]
    assert fake.include == [NET, NAME]
    assert "ariadne scope undo dec-1" in out


def test_add_no_and_non_tty_write_nothing(fake, capsys, monkeypatch):
    _tty(monkeypatch, "")
    assert main(["scope", "add", NAME]) == 1
    assert "Nicht geändert." in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["scope", "add", NAME]) == 1
    assert "Bestätigung nötig" in capsys.readouterr().err
    assert all(c[1].get("dry_run") for c in fake.calls if c[0] == "scope.change")
    assert fake.include == [NET]
    assert main(["scope", "add", NAME, "--yes"]) == 0 and fake.include == [NET, NAME]


def test_public_target_needs_not_customer(fake, capsys):
    assert main(["scope", "add", "www.example.com", "--yes"]) == 1
    out = capsys.readouterr().out
    assert "ausserhalb der Lab-Allowlist" in out and "--not-customer" in out
    assert fake.include == [NET]
    assert main(["scope", "add", "www.example.com", "--yes", "--not-customer"]) == 0
    assert fake.calls[-1][1]["not_customer"] is True


def test_invalid_and_hostile_targets(fake, capsys):
    assert main(["scope", "add", "a\x1b[31mb.lab", "--yes"]) == 1
    err = capsys.readouterr().err
    assert "\x1b" not in err
    assert main(["scope", "remove", "nope.lab", "--yes"]) == 1
    assert fake.include == [NET]


def test_undo_takes_latest_change(fake, capsys, monkeypatch):
    assert main(["scope", "add", NAME, "--yes"]) == 0
    assert main(["scope", "undo", "--yes"]) == 0
    rev = [c for c in fake.calls if c[0] == "scope.change" and c[1]["action"] == "revert"]
    assert rev and all(c[1]["decision_id"] == "dec-1" for c in rev)


def test_start_hint_shows_scope_and_command(monkeypatch, capsys):
    lines = scope_cli.add_hint([NAME, NET, "*.vantis.htb"], [NET])
    assert lines[1] == f"Scope jetzt: {NET}"
    assert lines[2] == f"Erweitern: ariadne scope add {NAME} '*.vantis.htb'"
    assert scope_cli.add_hint([NET], [NET])[-1] == "Alle Ziele stehen schon im Scope."
    assert "Ungültig" in scope_cli.add_hint(["a b"], [NET])[-1]

    monkeypatch.setattr(main_mod, "_call", lambda paths, op, **kw: {"include": [NET]})
    main_mod._targets_hint(None, [NAME])  # type: ignore[arg-type]
    out = capsys.readouterr().out
    assert f"Scope jetzt: {NET}" in out and f"ariadne scope add {NAME}" in out
    assert "nicht übernommen" not in out
