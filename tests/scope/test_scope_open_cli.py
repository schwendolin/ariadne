"""CLI zum offenen Scope (E131) mit Fake-ctl: ``ariadne scope`` (erste Zeile), ``scope open``/``close``
mit Rückfragen, ``ariadne start <neu>`` und ``project new`` ohne ``--target`` (Terminal, ohne Terminal,
Tippfehlerschutz) und ``ariadne status``."""

from __future__ import annotations

from typing import Any

import pytest

from ariadne.cli import main as main_mod
from ariadne.cli import scope as scope_cli
from ariadne.cli.main import main
from ariadne.daemon.client import CtlError
from ariadne.project.guardrails import LabAllowlist
from ariadne.scope.change import ScopeChangeError, plan_change

NET = "10.36.198.0/24"


class FakeDaemon:
    def __init__(self, include: list[str] | None = None, open_scope: bool = False,
                 not_customer: bool = False) -> None:
        self.include = [NET] if include is None else include
        self.open = open_scope
        self.not_customer = not_customer
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, paths: Any, op: str, *, start: bool = True, **args: Any) -> Any:
        self.calls.append((op, args))
        if op == "scope.show":
            return {"slug": "lab", "profile": "lab", "version": 1, "include": list(self.include),
                    "exclude": [], "open": self.open, "windows": [], "not_customer": self.not_customer,
                    "history": [], "project_id": "p1"}
        if op == "scope.change":
            settings = {"scope": {"include": self.include, "exclude": [], "windows": [], "open": self.open}}
            try:
                plan = plan_change(settings, args["action"], args.get("entries"), LabAllowlist.default())
            except ScopeChangeError as exc:
                raise CtlError(exc.code, str(exc)) from None
            need = (plan.opens or bool(plan.outside)) and not self.not_customer
            res = {**plan.view(), "version": 2, "needs_not_customer": need, "decision_id": None}
            if args.get("dry_run"):
                return res
            if need and args.get("not_customer") is not True:
                raise CtlError("guardrail", "x")
            self.include, self.open = plan.include, plan.open_after
            self.not_customer = self.not_customer or bool(args.get("not_customer"))
            return {**res, "decision_id": "dec-1"}
        raise AssertionError(op)


@pytest.fixture
def env(monkeypatch, tmp_path):
    for k in ("HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"):
        monkeypatch.setenv(k, str(tmp_path / k.lower()))


def _fake(monkeypatch, **kw: Any) -> FakeDaemon:
    f = FakeDaemon(**kw)
    monkeypatch.setattr(scope_cli, "_call", f.call)
    return f


def _tty(monkeypatch, *answers: str) -> list[str]:
    asked: list[str] = []
    it = iter(answers)
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)

    def ask(prompt: str) -> str:
        asked.append(prompt)
        return next(it, "")

    monkeypatch.setattr("builtins.input", ask)
    return asked


def test_show_first_line(env, monkeypatch, capsys):
    _fake(monkeypatch)
    assert main(["scope"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == "Scope: geschlossen (nur die Einschlüsse)"
    _fake(monkeypatch, open_scope=True)
    assert main(["scope"]) == 0
    assert capsys.readouterr().out.splitlines()[0] == (
        "Scope: offen (alles gilt als im Scope, ausser Ausschlüssen)")


def test_open_asks_effect_and_not_customer(env, monkeypatch, capsys):
    f = _fake(monkeypatch)
    asked = _tty(monkeypatch, "j", "j")
    assert main(["scope", "open"]) == 0
    out = capsys.readouterr().out
    assert asked == ["Kein Kundenauftrag? [j/N] ", "Übernehmen? [j/N] "]
    assert "auch öffentliche Ziele" in out and "Scope geöffnet (Version 2" in out
    assert f.open is True and f.calls[-1][1]["not_customer"] is True
    assert "entries" not in f.calls[-1][1]
    # schon offen: noop mit festem Text, nichts geschrieben
    n = len(f.calls)
    assert main(["scope", "open", "--yes"]) == 1
    assert "schon offen" in capsys.readouterr().err and len(f.calls) == n + 1


def test_open_refused_without_confirmation(env, monkeypatch, capsys):
    f = _fake(monkeypatch)
    asked = _tty(monkeypatch, "n")
    assert main(["scope", "open"]) == 1
    assert asked == ["Kein Kundenauftrag? [j/N] "] and f.open is False
    assert "Bestätigung fehlt" in capsys.readouterr().out
    # ohne Terminal: nur mit --yes und --not-customer
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["scope", "open", "--yes"]) == 1 and f.open is False
    assert main(["scope", "open", "--not-customer"]) == 1 and f.open is False
    assert "Bestätigung nötig" in capsys.readouterr().err
    assert main(["scope", "open", "--yes", "--not-customer"]) == 0 and f.open is True
    assert all(c[1].get("dry_run") or c[1].get("not_customer") for c in f.calls if c[0] == "scope.change")


def test_open_with_confirmed_not_customer_asks_once(env, monkeypatch, capsys):
    f = _fake(monkeypatch, not_customer=True)
    asked = _tty(monkeypatch, "j")
    assert main(["scope", "open"]) == 0
    assert asked == ["Übernehmen? [j/N] "] and f.open is True


def test_close_needs_include_and_asks(env, monkeypatch, capsys):
    f = _fake(monkeypatch, include=[], open_scope=True, not_customer=True)
    _tty(monkeypatch, "j")
    assert main(["scope", "close"]) == 1
    assert "Zuerst einen Eintrag hinzufügen: ariadne scope add <ziel>" in capsys.readouterr().err
    assert f.open is True
    f = _fake(monkeypatch, open_scope=True, not_customer=True)
    asked = _tty(monkeypatch, "j")
    assert main(["scope", "close"]) == 0
    out = capsys.readouterr().out
    assert asked == ["Übernehmen? [j/N] "] and "nur noch die Einschlüsse" in out and NET in out
    assert "Scope geschlossen (Version 2" in out and f.open is False
    assert main(["scope", "close", "--yes"]) == 1
    assert "schon geschlossen" in capsys.readouterr().err


class StartFake:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def call(self, paths: Any, op: str, *, start: bool = True, **args: Any) -> Any:
        self.calls.append((op, args))
        if op == "status":
            return {"operator": {"unlocked": True}, "project": None, "active": None}
        if op in ("start", "project.new"):
            return {"slug": args["slug"], "id": "p1", "profile": "lab", "workspace": "/w", "created": True,
                    "preroll": {}, "recording": 1, "held": 0, "opened": True}
        raise AssertionError(op)


@pytest.fixture
def start_env(env, monkeypatch):
    f = StartFake()
    monkeypatch.setattr(main_mod, "_call", f.call)
    monkeypatch.setattr(main_mod, "_client", lambda paths, **kw: None)
    monkeypatch.setattr(main_mod, "_pause_this_terminal", lambda paths: None)
    monkeypatch.setattr(main_mod, "_preroll_choice", lambda *a, **kw: (False, False))
    monkeypatch.setattr(main_mod, "_say_preroll", lambda *a, **kw: None)

    class Vault:
        def __init__(self, *a: Any) -> None:
            self.exists = True

    monkeypatch.setattr(main_mod, "OperatorVault", Vault)
    return f


def _starts(f: StartFake) -> list[dict[str, Any]]:
    return [a for op, a in f.calls if op in ("start", "project.new")]


def test_start_new_without_target_asks_in_terminal(start_env, monkeypatch, capsys):
    asked = _tty(monkeypatch, "j")
    assert main(["start", "neu"]) == 0
    q = ("Projekt neu gibt es noch nicht. Neu anlegen mit offenem Scope? Alles gilt dann als im Scope, "
         "auch öffentliche Ziele; nur ohne Kundenauftrag. [j/N] ")
    assert asked == [q]
    call = _starts(start_env)[-1]
    assert call["open_scope"] is True and call["not_customer"] is True and call["targets"] is None
    assert "Scope: offen" in capsys.readouterr().out


def test_start_typo_answer_no_creates_nothing(start_env, monkeypatch, capsys):
    asked = _tty(monkeypatch, "")
    assert main(["start", "vantsi"]) == 1
    assert len(asked) == 1 and "vantsi" in asked[0]
    assert _starts(start_env) == [] and start_env.calls == []  # nicht einmal der Daemon gefragt
    assert "Nicht angelegt" in capsys.readouterr().err


def test_start_without_terminal_needs_flags(start_env, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["start", "neu"]) == 1
    err = capsys.readouterr().err
    assert "--open-scope --not-customer" in err and "--target" in err
    assert main(["start", "neu", "--open-scope"]) == 1
    assert _starts(start_env) == []
    assert main(["start", "neu", "--open-scope", "--not-customer"]) == 0
    call = _starts(start_env)[-1]
    assert call["open_scope"] is True and call["not_customer"] is True
    # mit --target wie bisher, keine Rückfrage
    assert main(["start", "neu2", "--target", "10.0.0.0/24"]) == 0
    assert _starts(start_env)[-1]["open_scope"] is False


def test_start_open_scope_flag_in_terminal_asks_not_customer(start_env, monkeypatch, capsys):
    asked = _tty(monkeypatch, "n")
    assert main(["start", "neu", "--open-scope"]) == 1
    assert asked == ["Kein Kundenauftrag? [j/N] "] and _starts(start_env) == []


def test_project_new_without_target(start_env, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert main(["project", "new", "neu"]) == 1
    assert "ariadne project new neu --open-scope --not-customer" in capsys.readouterr().err
    assert main(["project", "new", "neu", "--open-scope", "--not-customer"]) == 0
    call = _starts(start_env)[-1]
    assert call["open_scope"] is True and call["targets"] == []
    asked = _tty(monkeypatch, "j")
    assert main(["project", "new", "neu3"]) == 0 and len(asked) == 1
    assert _starts(start_env)[-1]["open_scope"] is True


def test_status_shows_open_scope(env, monkeypatch, capsys):
    st = {"pid": 1, "version": "x", "operator": {"exists": True, "unlocked": True, "handle": "h"},
          "project": {"slug": "neu", "profile": "lab", "scope_open": True}, "active": None,
          "terminals": 0, "recording": 0, "terminal_states": []}
    monkeypatch.setattr(main_mod, "_call", lambda paths, op, **kw: st)
    monkeypatch.setattr(main_mod, "_web_line", lambda paths: "Web: aus")
    assert main(["status"]) == 0
    assert "Scope:    offen" in capsys.readouterr().out
    st["project"]["scope_open"] = False
    assert main(["status"]) == 0
    assert "Scope:" not in capsys.readouterr().out
