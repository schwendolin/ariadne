"""Reine Planung einer Scope-Änderung (E129) und Vorschläge (E130), ohne Daemon."""

from __future__ import annotations

import pytest

from ariadne import events
from ariadne.project.guardrails import LabAllowlist, is_public_name
from ariadne.project.settings import default_settings, parse_settings
from ariadne.scope.change import ScopeChangeError, plan_change, plan_revert, render_toml
from ariadne.scope.suggest import proposals, wildcard_of

ALLOW = LabAllowlist.default()


def _settings(include, exclude=()):
    return {"scope": {"include": list(include), "exclude": list(exclude), "windows": []}}


def test_add_remove_exclude_and_revert_compose():
    s = _settings(["10.36.198.0/24"], ["recovery.vantis.internal"])
    add = plan_change(s, "add", ["Recovery.Vantis.Internal.", "recovery.vantis.internal"], ALLOW)
    assert add.entries == ("recovery.vantis.internal",)
    assert add.include == ["10.36.198.0/24", "recovery.vantis.internal"] and add.exclude == []
    assert add.exclude_removed == ("recovery.vantis.internal",)
    assert add.verdicts == {"recovery.vantis.internal": "in"}
    later = plan_change(_settings(add.include, add.exclude), "exclude", ["10.36.198.99"], ALLOW)
    # Rückgängig der ersten Änderung auf dem späteren Stand: nur ihre Wirkung fällt weg
    rev = plan_revert(_settings(later.include, later.exclude), add.change(), "d1", ALLOW)
    assert rev.include == ["10.36.198.0/24"]
    assert rev.exclude == ["10.36.198.99", "recovery.vantis.internal"] and rev.revert_of == "d1"
    with pytest.raises(ScopeChangeError) as e:
        plan_revert(_settings(rev.include, rev.exclude), add.change(), "d1", ALLOW)
    assert e.value.code == "noop"


def test_add_inside_broader_exclude_reports_verdict():
    p = plan_change(_settings(["10.0.0.0/24"], ["10.0.0.0/28"]), "add", ["10.0.0.5"], ALLOW)
    assert p.verdicts == {"10.0.0.5": "excluded"}
    w = plan_change(_settings(["10.0.0.0/24"]), "add", ["*.vantis.internal"], ALLOW)
    assert w.verdicts == {"*.vantis.internal": "in"} and w.outside == ()


@pytest.mark.parametrize("bad", ["", " ", "a b", "x\x00.lab", "x.lab\n", "‮x.lab", "10.0.0.0/33", "a" * 300])
def test_invalid_entries(bad):
    with pytest.raises(ScopeChangeError) as e:
        plan_change(_settings(["10.0.0.0/24"]), "add", [bad], ALLOW)
    assert e.value.code == "invalid"


def test_errors_noop_not_listed_last_include_too_many():
    s = _settings(["10.0.0.0/24"])
    for op, entries, code in (("add", ["10.0.0.0/24"], "noop"), ("remove", ["x.lab"], "not_listed"),
                              ("remove", ["10.0.0.0/24"], "last_include"),
                              ("add", [f"h{i}.lab" for i in range(21)], "too_many")):
        with pytest.raises(ScopeChangeError) as e:
            plan_change(s, op, entries, ALLOW)
        assert e.value.code == code


def test_outside_lab_allowlist_and_public_names():
    p = plan_change(_settings(["10.0.0.0/24"]), "add", ["www.example.com", "8.8.8.8", "x.internal"], ALLOW)
    assert p.outside == ("www.example.com", "8.8.8.8")
    assert is_public_name("www.example.com") and not is_public_name("*.vantis.internal")
    private = ("internal", "local", "lab", "htb", "test", "lan", "home", "localdomain")
    assert not any(is_public_name(f"a.{t}") for t in private)


def test_render_toml_keeps_other_settings_and_validates_event():
    text = default_settings(name="x", profile="lab", include=["10.0.0.0/24"])
    new = render_toml(text, ["10.0.0.0/24", "a.lab"], ["10.0.0.9"])
    data = parse_settings(new)
    assert data["scope"]["include"] == ["10.0.0.0/24", "a.lab"] and data["scope"]["exclude"] == ["10.0.0.9"]
    assert data["llm"] == parse_settings(text)["llm"]
    p = plan_change(data, "remove", ["a.lab"], ALLOW)
    h = events.validate_header("d.scope.update", {"version": 2, "toml": new, "change": p.change("Grund")})
    assert h["change"]["op"] == "remove" and h["change"]["include_removed"] == ["a.lab"]
    # ältere Einträge ohne change bleiben gültig
    assert "change" not in events.validate_header("d.scope.update", {"version": 1, "toml": text})
    with pytest.raises(ValueError):
        events.validate_header("d.scope.update", {"version": 2, "toml": new, "change": {"op": "drop"}})


def test_proposals_for_warning_targets():
    assert [(p["entry"], p["kind"]) for p in proposals("http://recovery.vantis.internal/login")] == [
        ("recovery.vantis.internal", "url_host"), ("*.vantis.internal", "wildcard")]
    assert [(p["entry"], p["kind"]) for p in proposals("ms2.lab")] == [("ms2.lab", "name")]
    assert [p["entry"] for p in proposals("10.36.199.4:8080")] == ["10.36.199.4"]
    assert [p["entry"] for p in proposals("10.36.199.0/24")] == ["10.36.199.0/24"]
    assert proposals("0x0a.1") == [] or all(p["kind"] == "ip" for p in proposals("0x0a.1"))
    assert proposals("a\x1bb") == [] and proposals("") == []
    assert wildcard_of("ms2.lab") is None and wildcard_of("a.b.lab") == "*.b.lab"
