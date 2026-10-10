from __future__ import annotations

from types import SimpleNamespace

import pytest

from ariadne.ctxrules import split_command
from ariadne.parsers import registry
from ariadne.parsers.api import Parser
from ariadne.parsers.registry import (
    ALL_PARSERS,
    PluginError,
    companions_for,
    default_registry,
    load_plugins,
    validate_parser,
)


def test_builtin_order_and_protocol():
    assert list(ALL_PARSERS) == ["nmap.xml", "nmap.text", "listener.callback", "regex.net"]
    parsers = default_registry()
    assert [p.id for p in parsers] == list(ALL_PARSERS)
    assert all(isinstance(p, Parser) for p in parsers)


@pytest.mark.parametrize(
    "cmd,cwd,expected",
    [
        (
            "nmap -sV -oA scans/lame 10.10.10.3",
            "/home/kali/lame",
            [
                "/home/kali/lame/scans/lame.xml",
                "/home/kali/lame/scans/lame.nmap",
                "/home/kali/lame/scans/lame.gnmap",
            ],
        ),
        ("sudo nmap -sS -oX /tmp/s.xml -oN s.txt 10.0.0.0/24", "/w", ["/tmp/s.xml", "/w/s.txt"]),
        ("proxychains4 -q nmap -sT -Pn -oA b 172.16.1.5", "/w", ["/w/b.xml", "/w/b.nmap", "/w/b.gnmap"]),
        ("sudo -u root proxychains -f p.conf nmap -oX x.xml 1.2.3.4", "/w", ["/w/x.xml"]),
        ("nmap -oA ~/scans/x 1.2.3.4", "/w", ["~/scans/x.xml", "~/scans/x.nmap", "~/scans/x.gnmap"]),
        ("ffuf -u http://x/FUZZ -o out.json", "/w", []),
        ("nmap -oX", "/w", []),
    ],
)
def test_companions_for(cmd, cwd, expected):
    assert companions_for(split_command(cmd), cwd) == expected


def test_companions_survive_broken_parser():
    class Broken:
        id = "broken"

        def companions(self, argv, cwd):
            raise RuntimeError("kaputt")

    good = default_registry()[0]
    assert companions_for(["nmap", "-oX", "a.xml"], "/w", [Broken(), good]) == ["/w/a.xml"]


class _Plugin:
    id = "demo.plugin"
    version = "1"
    trust = "tool_text"
    auto_eligible = False

    def match(self, unit):
        return 0

    def parse(self, unit):
        return iter(())

    def companions(self, argv, cwd):
        return []


def _fake_eps(monkeypatch, eps):
    monkeypatch.setattr(
        registry.metadata, "entry_points", lambda group: eps if group == "ariadne.parsers" else []
    )


def _ep(name, obj, version="1.0", loaded=None):
    def load():
        if loaded is not None:
            loaded.append(name)
        return obj

    return SimpleNamespace(name=name, load=load, dist=SimpleNamespace(version=version))


def test_plugins_only_from_allowlist(monkeypatch):
    loaded: list[str] = []
    _fake_eps(monkeypatch, [_ep("demo", _Plugin, loaded=loaded), _ep("other", _Plugin, loaded=loaded)])
    assert [p.id for p in default_registry()] == list(ALL_PARSERS)
    assert loaded == []  # ohne Allowlist wird nichts importiert
    ids = [p.id for p in default_registry(["demo"])]
    assert ids == [*ALL_PARSERS, "demo.plugin"]
    assert loaded == ["demo"]


def test_plugin_version_pin(monkeypatch):
    _fake_eps(monkeypatch, [_ep("demo", _Plugin, version="2.0")])
    assert load_plugins(["demo==1.0"]) == []
    assert [p.id for p in load_plugins(["demo==2.0"])] == ["demo.plugin"]


def test_invalid_plugins_are_rejected(monkeypatch):
    class Shadow(_Plugin):
        id = "nmap.xml"

    class UserTrust(_Plugin):
        id = "x.user"
        trust = "user"

    class NoParse:
        id = "x.noparse"
        version = "1"
        trust = "heuristic"
        auto_eligible = False

    _fake_eps(
        monkeypatch,
        [_ep("a", Shadow), _ep("b", UserTrust), _ep("c", NoParse), _ep("d", RuntimeError("load kaputt"))],
    )
    assert load_plugins(["a", "b", "c", "d"]) == []
    with pytest.raises(PluginError):
        validate_parser(Shadow(), plugin=True)
