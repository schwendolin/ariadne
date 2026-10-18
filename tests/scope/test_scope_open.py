"""Offener Scope (E131) und die Entscheide E132/E133 ohne Daemon: Matcher, Einstellungen, Anlegen ohne
Ziele, Planung von open/close mit noop, no_include, Rückgängig und ``broad``."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ariadne import events
from ariadne.project.guardrails import LabAllowlist
from ariadne.project.service import GuardrailError, ProjectError, ProjectService
from ariadne.project.settings import SettingsError, default_settings, parse_settings
from ariadne.scope.change import ScopeChangeError, is_broad, plan_change, plan_revert, render_toml
from ariadne.scope.matcher import ScopeMatcher

ALLOW = LabAllowlist.default()


def _m(include=(), exclude=(), windows=(), open_scope=True) -> ScopeMatcher:
    return ScopeMatcher.from_settings({"scope": {"include": list(include), "exclude": list(exclude),
                                                 "windows": list(windows), "open": open_scope}}, 3)


def test_matcher_open_takes_everything_but_excludes_and_special():
    m = _m(exclude=["8.8.4.4", "*.evil.com", "https://github.com/admin"])
    for ident in ("8.8.8.8", "ip:default/1.1.1.1", "github.com", "fqdn:www.example.com",
                  "https://github.com/login", "url:http://8.8.8.8:8080/x", "svc:github.com|443/tcp",
                  "2001:4860:4860::8888", "9.9.0.0/16", "10.0.0.1-50", "WWW.Example.COM."):
        v = m.check(ident)
        assert v.verdict == "in" and v.rule == "open", (ident, v)
    assert m.check("8.8.4.4").verdict == "excluded" and m.check("8.8.0.0/16").verdict == "excluded"
    assert m.check("a.evil.com").verdict == "excluded"
    assert m.check("https://github.com/admin/x").verdict == "excluded"
    assert m.check("https://github.com/%61dmin").verdict == "excluded"  # Ausschluss fail-closed
    # Sonderadressen nie implizit, auch nicht offen; nur exakt gelistet
    for special in ("127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.1", "255.255.255.255",
                    "0.0.0.0", "::", "http://127.0.0.1/", "0.0.0.0/0", "127.0.0.0/8"):
        assert _m().check(special).verdict == "out", special
    assert _m(include=["127.0.0.1"]).check("127.0.0.1").verdict == "in"
    # mehrdeutige Lesart: strengstes Urteil (0x7f.1 ist 127.0.0.1)
    assert m.check("0x7f.1").verdict == "out"
    # unlesbar bleibt unklar
    assert m.check("").verdict == "unknown"
    # geschlossen (fehlt oder nicht true): wie bisher
    closed = ScopeMatcher.from_settings({"scope": {"include": ["10.0.0.0/24"]}}, 1)
    assert closed.check("8.8.8.8").verdict == "out" and closed.open is False
    assert ScopeMatcher.from_settings({"scope": {"open": "true"}}, 1).open is False  # nur echtes true
    assert ScopeMatcher.from_settings({"scope": {"open": 1}}, 1).open is False


def test_matcher_open_respects_windows():
    win = [{"days": "mon-fri", "from": "09:00", "to": "17:00", "tz": "UTC"}]
    m = _m(windows=win)
    inside = int(datetime(2026, 10, 14, 10, 0, tzinfo=UTC).timestamp() * 1e9)  # Mittwoch
    outside = int(datetime(2026, 10, 18, 10, 0, tzinfo=UTC).timestamp() * 1e9)  # Sonntag
    assert m.check("8.8.8.8", inside).verdict == "in"
    assert m.check("github.com", outside).verdict == "outside_window"
    assert m.check("8.8.8.8").verdict == "in"  # ohne Zeitpunkt


def test_settings_open_only_bool():
    text = default_settings(name="x", profile="lab", include=[], open_scope=True)
    data = parse_settings(text)
    assert data["scope"]["open"] is True and data["scope"]["include"] == []
    closed = default_settings(name="x", profile="lab", include=["a.lab"])
    assert parse_settings(closed)["scope"]["open"] is False
    bad = text.replace("open = true", 'open = "yes"')
    with pytest.raises(SettingsError):
        parse_settings(bad)
    assert ScopeMatcher.from_settings(text, 1).check("8.8.8.8").verdict == "in"


def test_create_without_targets_needs_open_scope_and_not_customer(paths, operator):
    svc = ProjectService(paths, operator)
    with pytest.raises(ProjectError) as e:
        svc.create("leer", [])
    assert "--open-scope" in str(e.value)
    with pytest.raises(GuardrailError) as g:
        svc.create("leer", [], open_scope=True)
    assert "kein Kundenauftrag" in str(g.value)
    with pytest.raises(ProjectError):
        svc.create("leer", [], open_scope=True, not_customer=True, profile="customer")
    assert not (paths.projects_root / "leer").exists()
    info = svc.create("leer", [], open_scope=True, not_customer=True)
    p = svc.open(info.slug)
    try:
        assert p.settings["scope"]["open"] is True and p.settings["scope"]["include"] == []
        kinds = [r.kind for r in p.journal.iter_events(kinds=["d.lab.not_customer"])]
        assert kinds == ["d.lab.not_customer"]
    finally:
        p.close()


def _s(include, exclude=(), open_scope=False):
    return {"scope": {"include": list(include), "exclude": list(exclude), "windows": [], "open": open_scope}}


def test_plan_open_close_noop_no_include_and_revert():
    p = plan_change(_s(["10.0.0.0/24"]), "open", None, ALLOW)
    assert p.opens and p.open_after and not p.open_before and p.include == ["10.0.0.0/24"]
    ch = p.change()
    assert ch["op"] == "open" and ch["open_before"] is False and ch["open_after"] is True
    hdr = events.validate_header("d.scope.update", {"version": 2, "toml": "x", "change": ch})
    assert hdr["change"]["op"] == "open"
    with pytest.raises(ScopeChangeError) as e:
        plan_change(_s(["10.0.0.0/24"], open_scope=True), "open", None, ALLOW)
    assert e.value.code == "noop"
    with pytest.raises(ScopeChangeError) as e:
        plan_change(_s(["10.0.0.0/24"]), "close", None, ALLOW)
    assert e.value.code == "noop"
    with pytest.raises(ScopeChangeError) as e:
        plan_change(_s([], open_scope=True), "close", None, ALLOW)
    assert e.value.code == "no_include" and "ariadne scope add <ziel>" in str(e.value)
    with pytest.raises(ScopeChangeError) as e:
        plan_change(_s([]), "open", ["x.lab"], ALLOW)
    assert e.value.code == "invalid"
    c = plan_change(_s(["a.lab"], open_scope=True), "close", None, ALLOW)
    assert not c.opens and c.open_before and not c.open_after
    # bei offenem Scope darf der letzte Einschluss weg, geschlossen nicht
    r = plan_change(_s(["a.lab"], open_scope=True), "remove", ["a.lab"], ALLOW)
    assert r.include == [] and r.open_after is True
    with pytest.raises(ScopeChangeError) as e:
        plan_change(_s(["a.lab"]), "remove", ["a.lab"], ALLOW)
    assert e.value.code == "last_include"
    # Rückgängig: open -> geschlossen, close -> offen (opens), mit denselben Prüfungen
    rv = plan_revert(_s(["10.0.0.0/24"], open_scope=True), ch, "d1", ALLOW)
    assert rv.open_after is False and rv.change()["open_after"] is False and rv.op == "revert"
    rv2 = plan_revert(_s(["a.lab"]), c.change(), "d2", ALLOW)
    assert rv2.opens
    with pytest.raises(ScopeChangeError) as e:  # Öffnen rückgängig, aber kein Einschluss mehr
        plan_revert(_s([], open_scope=True), ch, "d1", ALLOW)
    assert e.value.code == "no_include"
    with pytest.raises(ScopeChangeError) as e:  # schon wieder geschlossen
        plan_revert(_s(["a.lab"]), ch, "d1", ALLOW)
    assert e.value.code == "noop"
    # Snapshot mit open
    text = default_settings(name="x", profile="lab", include=["a.lab"])
    assert parse_settings(render_toml(text, ["a.lab"], [], True))["scope"]["open"] is True
    assert parse_settings(render_toml(text, ["a.lab"], []))["scope"]["open"] is False


def test_broad_e133():
    for e, b in (("10.0.0.0/16", False), ("10.0.0.0/15", True), ("0.0.0.0/0", True), ("8.8.8.8", False),
                 ("10.0.0.0-10.1.0.0", True), ("10.0.0.0-10.0.255.255", False), ("2001:db8::/48", False),
                 ("2001:db8::/47", True), ("a.lab", False), ("*.vantis.htb", False)):
        assert is_broad(e) is b, e
    assert plan_change(_s(["a.lab"]), "add", ["10.0.0.0/8"], ALLOW).view()["broad"] is True
    assert plan_change(_s(["a.lab"]), "add", ["10.0.0.0/24"], ALLOW).view()["broad"] is False
    with pytest.raises(ScopeChangeError):  # *.<eine Endung> bleibt abgelehnt
        plan_change(_s(["a.lab"]), "add", ["*.com"], ALLOW)
