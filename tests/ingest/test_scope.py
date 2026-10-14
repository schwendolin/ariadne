"""Scope: Normalisierung, ScopeMatcher und Zeitfenster (Architektur 5.8)."""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo

import pytest

from ariadne.scope.api import ScopeChecker, Verdict
from ariadne.scope.matcher import ScopeMatcher
from ariadne.scope.normalize import (
    ipv4_candidates,
    mixed_script,
    normalize_hostname,
    normalize_ip,
    normalize_url,
    to_identifier,
)

# --------------------------------------------------------------------------- normalize


@pytest.mark.parametrize("raw,expected", [
    ("Lame.HTB.", "fqdn:lame.htb"),
    ("WEB01", "fqdn:web01"),
    ("münchen.de", "fqdn:xn--mnchen-3ya.de"),
    ("xn--mnchen-3ya.de", "fqdn:xn--mnchen-3ya.de"),
    ("ｅｘａｍｐｌｅ.htb", "fqdn:example.htb"),  # Vollbreite wird per IDNA abgebildet
    ("_ldap._tcp.corp.local", "fqdn:_ldap._tcp.corp.local"),
    ("ab--cd.htb", "fqdn:ab--cd.htb"),
    ("name:Web01", "fqdn:web01"),
    ("10.10.10.5", "ip:default/10.10.10.5"),
    ("10.1", "ip:default/10.0.0.1"),
    ("167772165", "ip:default/10.0.0.5"),
    ("0x0A000005", "ip:default/10.0.0.5"),
    ("0xa.0x1", "ip:default/10.0.0.1"),
    ("012.0.0.1", None),  # oktal 10.0.0.1 oder dezimal 12.0.0.1: mehrdeutig
    ("10.10.10.5.", "ip:default/10.10.10.5"),
    ("::ffff:10.0.0.5", "ip:default/10.0.0.5"),
    ("[::ffff:a00:5]", "ip:default/10.0.0.5"),
    ("FE80::1%eth0", "ip:default/fe80::1"),
    ("2001:DB8::0:1", "ip:default/2001:db8::1"),
    ("ip:default/010.10.10.5", None),
    ("ip:other/10.0.0.1", None),
    ("HTTP://LAME.htb:80/a/../b#frag", "url:http://lame.htb/b"),
    ("https://10.1:443/x?y=1", "url:https://10.0.0.1/x?y=1"),
    ("http://[::ffff:10.0.0.5]:8080/", "url:http://10.0.0.5:8080/"),
    ("http://x.htb/public/%2e%2e/admin", "url:http://x.htb/admin"),
    ("http://x.htb/über", "url:http://x.htb/%C3%BCber"),
    ("https://user:pw@x.htb/", None),
    ("http://x.htb\\@evil.com/", None),
    ("http://x.htb/\x00", None),
    ("http://x.htb\t/", None),
    ("ftp://x.htb/", None),
    ("javascript:alert(1)", None),
    ("http://010.1.1.1/", None),
    ("http://1.2.3.4.5/", None),
    ("http://x%2ehtb/", None),
    ("http://x.htb:99999/", None),
    ("pаypal.com", None),  # kyrillisches а
    ("xn--pypal-4ve.com", None),
    ("host:445", None),
    ("1.2.3.4.5", None),
    ("-bad.htb", None),
    ("a" * 64 + ".htb", None),
    ("x‮.htb", None),
    ("", None),
])
def test_to_identifier(raw, expected):
    assert to_identifier(raw) == expected


def test_ipv4_candidates_strictest_readings():
    assert ipv4_candidates("010.1.1.1") == ["8.1.1.1", "10.1.1.1"]
    assert ipv4_candidates("10.1") == ["10.0.0.1"]
    assert ipv4_candidates("09.1.1.1") == [None, "9.1.1.1"]
    assert ipv4_candidates("lame.htb") is None
    assert normalize_ip("4294967296") is None
    assert normalize_ip("0x") == "0.0.0.0"


def test_hostname_rules():
    assert normalize_hostname("x.y.123") is None  # endet auf Zahl: keine Hostname-Form
    assert normalize_hostname("good-host.lab") == "good-host.lab"
    assert mixed_script("pаypal") and not mixed_script("paypal") and not mixed_script("日本語")
    assert normalize_url("http://LAME.htb") == "http://lame.htb/"


# --------------------------------------------------------------------------- matcher

SETTINGS = {
    "scope": {
        "include": ["10.10.10.0/24", "lame.htb", "*.lame.htb", "172.16.0.1-20", "127.0.0.1",
                    "http://ext.example/app/", "fe80::5", "2001:db8::/64"],
        "exclude": ["10.10.10.1", "admin.lame.htb", "http://lame.htb/logout", "10.10.10.128/25"],
    }
}


@pytest.fixture
def scope() -> ScopeMatcher:
    return ScopeMatcher.from_settings(SETTINGS, 3)


@pytest.mark.parametrize("ident,verdict", [
    ("10.10.10.5", "in"),
    ("ip:default/10.10.10.5", "in"),
    ("10.10.10.1", "excluded"),
    ("10.10.10.200", "excluded"),
    ("10.10.11.5", "out"),
    ("lame.htb", "in"),
    ("LAME.HTB.", "in"),
    ("dev.lame.htb", "in"),
    ("a.b.lame.htb", "in"),
    ("xlame.htb", "out"),  # Wildcard nur an Label-Grenzen
    ("admin.lame.htb", "excluded"),
    ("fqdn:dev.lame.htb", "in"),
    ("172.16.0.15", "in"),
    ("172.16.0.21", "out"),
    ("127.0.0.1", "in"),  # exakt gelistete Loopback-Adresse
    ("127.0.0.2", "out"),
    ("0.0.0.0", "out"),
    ("::", "out"),
    ("169.254.1.1", "out"),
    ("fe80::5", "in"),
    ("fe80::6", "out"),
    ("2001:db8::abcd", "in"),
    ("::ffff:10.10.10.5", "in"),
    ("167772165", "out"),  # = 10.0.0.5
    ("012.10.10.5", "out"),  # oktal 10.10.10.5 (in) oder dezimal 12.10.10.5 (out): strengstes gilt
    ("010.010.010.005", "out"),
    ("svc:ip:default/10.10.10.5|tcp/445", "in"),
    ("svc:fqdn:admin.lame.htb|tcp/80", "excluded"),
    ("url:http://dev.lame.htb/x", "in"),
    ("http://lame.htb/logout?x=1", "excluded"),
    ("http://lame.htb/public/../logout", "excluded"),
    ("http://ext.example/app/page", "in"),
    ("http://ext.example/other", "out"),
    ("http://user@lame.htb/", "unknown"),
    ("10.10.10.0/25", "excluded"),  # überlappt den Ausschluss .1
    ("10.10.10.2-10", "in"),
    ("10.10.10.0/16", "excluded"),
    ("mac:aa:bb:cc:dd:ee:ff", "unknown"),
    ("pаypal.lame.htb", "unknown"),
    ("straße.lame.htb", "unknown"),  # IDNA2003 macht strasse daraus, curl xn--strae-oqa
    ("http://straße.lame.htb/", "unknown"),
    ("http://lame.htb/%6Cogout", "excluded"),  # Ausschluss mit kodiertem Buchstaben
    ("http://lame.htb/LOGOUT", "excluded"),
    ("http://lame.htb//logout", "excluded"),
    ("http://lame.htb/logout;jsessionid=1", "excluded"),
    ("http://lame.htb/x/..%2flogout", "excluded"),
    ("http://lame.htb/x/..%252flogout", "excluded"),
    ("http://lame.htb/logoutx", "in"),
    ("", "unknown"),
    ("10.10.10.*", "unknown"),
])
def test_matcher(scope, ident, verdict):
    v = scope.check(ident)
    assert isinstance(v, Verdict) and v.scope_version == 3
    assert v.verdict == verdict, (ident, v)


def test_matcher_protocol_and_rules(scope):
    assert isinstance(scope, ScopeChecker)
    assert scope.check("10.10.10.5").rule == "include:10.10.10.0/24"
    assert scope.check("10.10.10.1").rule == "exclude:10.10.10.1"
    assert scope.check("127.0.0.2").rule == "special:loopback"
    assert not scope.check("unknown-thing").is_in


def test_special_ranges_only_exact():
    m = ScopeMatcher(include=["0.0.0.0/0", "::/0"], version=1)
    for addr in ("127.0.0.1", "0.0.0.0", "169.254.10.10", "::1", "::", "fe80::1", "224.0.0.1"):
        assert m.check(addr).verdict == "out", addr
    assert m.check("8.8.8.8").verdict == "in"


def test_invalid_rules_are_reported():
    m = ScopeMatcher.from_settings('[scope]\ninclude = ["10.0.0.0/33", "*.10.0.0", "ok.lab", 5]\n', 1)
    assert m.check("ok.lab").is_in
    assert len(m.errors) == 3


def test_name_never_matches_ip_rule():
    m = ScopeMatcher(include=["10.10.10.0/24"], version=1)
    assert m.check("host.lab").verdict == "out"


# --------------------------------------------------------------------------- Zeitfenster


def _ns(y, mo, d, h, mi, tz="UTC"):
    return int(datetime(y, mo, d, h, mi, tzinfo=ZoneInfo(tz)).timestamp()) * 1_000_000_000


@pytest.fixture
def windowed() -> ScopeMatcher:
    return ScopeMatcher.from_settings({"scope": {
        "include": ["10.10.10.0/24"],
        "windows": [{"days": "mon-fri", "from": "08:00", "to": "18:00", "tz": "Europe/Zurich"}],
    }}, 2)


def test_window_only_with_time(windowed):
    assert windowed.check("10.10.10.5").verdict == "in"


@pytest.mark.parametrize("when,verdict", [
    (_ns(2026, 3, 27, 7, 30), "in"),  # Fr 08:30 MEZ
    (_ns(2026, 3, 27, 6, 30), "outside_window"),  # Fr 07:30 MEZ
    (_ns(2026, 3, 30, 6, 30), "in"),  # Mo nach Umstellung: 08:30 MESZ
    (_ns(2026, 3, 30, 16, 30), "outside_window"),  # Mo 18:30 MESZ
    (_ns(2026, 3, 30, 15, 59), "in"),  # Mo 17:59 MESZ
    (_ns(2026, 3, 28, 10, 0), "outside_window"),  # Samstag
    (_ns(2026, 10, 26, 7, 0), "in"),  # Mo nach Rückstellung: 08:00 MEZ
    (_ns(2026, 10, 23, 6, 30), "in"),  # Fr 08:30 MESZ
])
def test_window_with_dst(windowed, when, verdict):
    assert windowed.check("10.10.10.5", when).verdict == verdict


def test_window_does_not_make_out_in(windowed):
    assert windowed.check("10.10.99.5", _ns(2026, 3, 27, 7, 30)).verdict == "out"


def test_window_over_midnight_and_invalid():
    m = ScopeMatcher.from_settings({"scope": {"include": ["10.0.0.1"], "windows": [
        {"days": ["fri"], "from": "22:00", "to": "06:00", "tz": "UTC"}]}}, 1)
    assert m.check("10.0.0.1", _ns(2026, 3, 27, 23, 0)).verdict == "in"  # Fr 23:00
    assert m.check("10.0.0.1", _ns(2026, 3, 28, 5, 59)).verdict == "in"  # Sa 05:59, Start Freitag
    assert m.check("10.0.0.1", _ns(2026, 3, 28, 6, 0)).verdict == "outside_window"
    assert m.check("10.0.0.1", _ns(2026, 3, 27, 5, 0)).verdict == "outside_window"  # Fr früh
    bad = ScopeMatcher.from_settings({"scope": {"include": ["10.0.0.1"], "windows": [
        {"days": "funday", "from": "25:00", "tz": "Mars/Base"}]}}, 1)
    assert bad.errors
    assert bad.check("10.0.0.1", _ns(2026, 3, 27, 12, 0)).verdict == "outside_window"  # fail-closed
    assert datetime.now(UTC).year >= 2026


def test_idna_deviation_names_rejected_as_targets():
    from ariadne.project.guardrails import InvalidTarget, parse_target

    with pytest.raises(InvalidTarget):
        parse_target("straße.htb")
    assert parse_target("xn--strae-oqa.htb").value == "xn--strae-oqa.htb"
