"""Befehlsbibliothek (E68, A 6.1 Punkte 1 bis 6): Lint beim Laden, Rendern nur mit sicheren Werten,
``shlex.split`` ergibt genau die erwarteten Wörter, und echte Shells (bash, dash, zsh, auch mit
``EXTENDED_GLOB``) zerlegen jeden gerenderten Befehl genauso."""

from __future__ import annotations

import re
import shlex
import shutil
import subprocess

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ariadne.rules.encoders import SHELL_META, Scope
from ariadne.rules.templates import SLOTS, TEMPLATES, Template, TemplateError, lint, render, skeleton

SCOPE = Scope(ip=lambda a: "in" if a.startswith("192.168.56.") or a.startswith("fd00:56:") else "out")
SAMPLE = {
    "host.ip": "192.168.56.101",
    "service.port": 8180,
    "service.url": "http://192.168.56.101:8180/",
    "service.product": "Apache Tomcat",
    "service.version": "5.5",
}
SHELLS = [
    pytest.param(["bash", "--norc", "--noprofile", "-c"], id="bash"),
    pytest.param(["dash", "-c"], id="dash"),
    pytest.param(["zsh", "-f", "-c"], id="zsh"),
    pytest.param(["zsh", "-f", "-o", "extendedglob", "-c"], id="zsh-extendedglob"),
]


def shell_argv(shell: list[str], command: str) -> list[str]:
    """argv, die eine echte Shell aus ``command`` macht (``printf`` statt des Werkzeugs, nichts läuft)."""
    if shutil.which(shell[0]) is None:
        pytest.skip(f"{shell[0]} fehlt")
    out = subprocess.run(
        [*shell, "printf '%s\\0' " + command],
        capture_output=True,
        timeout=10,
        check=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LC_ALL": "C"},
    )
    return out.stdout.decode().split("\0")[:-1]


def test_library_passes_lint_and_has_unique_ids():
    assert len(TEMPLATES) >= 20
    for t in TEMPLATES.values():
        lint(t)
        _tokens, slots = skeleton(t.text)
        assert slots and all(s in SLOTS for s in slots)


@pytest.mark.parametrize(
    "text",
    [
        "nmap -p {service.port} {host.ip}; id",  # Metazeichen im festen Text
        "nmap $(id) {host.ip}",
        "nmap {host.ip}\n",
        "nmap  {host.ip}",  # doppeltes Leerzeichen
        "nmap {host.secret}",  # unbekannter Slot
        "nmap {host.ip}{service.port}",  # zwei Slots ohne Trenner
        "searchsploit x{service.product}",  # words nicht allein
        "nmap {host.ip",  # Klammer
        "curl {host.ip}",  # Werkzeug passt nicht
        "nmap ü {host.ip}",
        "nmap 'x' {host.ip}",  # Anführungszeichen nur als leeres Argument ''
    ],
)
def test_lint_rejects_bad_templates(text):
    with pytest.raises(TemplateError):
        lint(Template("bad", "nmap", "x", text))


@pytest.mark.parametrize("tid", sorted(TEMPLATES))
def test_every_template_renders_with_safe_values(tid):
    t = TEMPLATES[tid]
    res = render(t, SAMPLE, SCOPE)
    assert res["rendered"] and res["blocked_reason"] is None
    cmd = res["command"]
    assert cmd and not cmd.endswith(("\n", "\r")) and "".join(p["text"] for p in res["parts"]) == cmd
    assert res["values"][0] == {
        "slot": "tool",
        "type": "word",
        "label": "Werkzeug",
        "value": t.tool,
        "ctrl": False,
        "target": False,
        "safe": True,
    }
    assert [v["slot"] for v in res["values"][1:]] == list(dict.fromkeys(skeleton(t.text)[1]))
    assert all(v["target"] and v["safe"] for v in res["values"][1:])
    targets = [p["text"] for p in res["parts"] if p["target"]]
    assert targets and all(x in [str(v["value"]) for v in res["values"]] for x in targets)


@pytest.mark.parametrize("tid", sorted(TEMPLATES))
@pytest.mark.parametrize("shell", SHELLS)
def test_real_shells_split_like_shlex(tid, shell):
    cmd = render(TEMPLATES[tid], SAMPLE, SCOPE)["command"]
    assert shell_argv(shell, cmd) == shlex.split(cmd)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("share", ["C$", "IPC$", "ADMIN$", "tmp"])
def test_dollar_at_end_of_share_is_literal_in_real_shells(shell, share):
    """``share`` erlaubt ``$`` nur am Ende (``C$``); dort ist es in allen Shells ein Zeichen."""
    from ariadne.rules.encoders import encode

    e = encode("share", share)
    assert e.safe
    cmd = f"smbclient //192.168.56.101/{e.text} -N"
    assert shell_argv(shell, cmd) == shlex.split(cmd) == ["smbclient", f"//192.168.56.101/{share}", "-N"]


def test_ipv6_variant_uses_nmap_6():
    t = TEMPLATES["nmap-full-tcp"]
    res = render(t, {"host.ip": "fd00:56::110"}, SCOPE, ipv6=True)
    assert res["command"] == "nmap -6 -p- -T4 fd00:56::110"
    url = render(TEMPLATES["curl-head"], {"service.url": "http://[fd00:56::110]:80/"}, SCOPE, ipv6=True)
    assert not url["rendered"] and url["blocked_reason"] == "shell_meta"


def test_missing_slot_and_out_of_scope_block():
    t = TEMPLATES["nmap-ftp-anon"]
    res = render(t, {"host.ip": "192.168.56.101"}, SCOPE)
    assert not res["rendered"] and res["blocked_reason"] == "invalid" and res["command"] is None
    res = render(t, {"host.ip": "10.10.10.3", "service.port": 21}, SCOPE)
    assert res["blocked_reason"] == "out_of_scope" and res["parts"] == []
    assert [v["safe"] for v in res["values"]] == [True, True, False]


def test_blocked_values_are_shown_visible_and_flagged():
    res = render(
        TEMPLATES["searchsploit"], {"service.product": "nginx\x1b[2J", "service.version": "1.0"}, SCOPE
    )
    assert not res["rendered"] and res["blocked_reason"] == "control"
    prod = res["values"][1]
    assert prod == {
        "slot": "service.product",
        "type": "words",
        "label": "Produkt",
        "value": "nginx<ESC>[2J",
        "ctrl": True,
        "target": True,
        "safe": False,
    }


_HOSTILE = st.sampled_from(
    list("abcXYZ019._+-/")
    + [" "] * 3
    + sorted(SHELL_META)
    + ["\n", "\r", "\x1b", "\x00", "\u202e", "\u200b", "\u2028", "р", "•", "$", "'", '"', "\\"]
)
_INERT = re.compile(r"[A-Za-z0-9._:/@=%+ '-]*")


@settings(max_examples=500, deadline=None, derandomize=True, database=None)
@given(product=st.text(_HOSTILE, min_size=1, max_size=30), version=st.text(_HOSTILE, min_size=1, max_size=12))
def test_property_searchsploit_renders_exact_argv_or_nothing(product, version):
    """Jede gerenderte Vorlage zerfällt mit ``shlex.split`` in genau Werkzeug, Produktwörter und Version
    und enthält nur Zeichen ohne Bedeutung für die Shell; sonst gibt es keinen Befehl."""
    res = render(TEMPLATES["searchsploit"], {"service.product": product, "service.version": version}, SCOPE)
    if not res["rendered"]:
        assert res["command"] is None and res["parts"] == []
        assert res["blocked_reason"] in ("shell_meta", "control", "newline", "non_ascii", "invalid")
        return
    cmd = res["command"]
    assert shlex.split(cmd) == ["searchsploit", *product.split(" "), version]
    assert _INERT.fullmatch(cmd) and not cmd.endswith("\n")


@settings(max_examples=300, deadline=None, derandomize=True, database=None)
@given(ip=st.text(_HOSTILE, min_size=1, max_size=20), port=st.text(_HOSTILE, min_size=1, max_size=6))
def test_property_ip_and_port_slots(ip, port):
    res = render(TEMPLATES["nmap-ftp-anon"], {"host.ip": ip, "service.port": port}, SCOPE)
    if res["rendered"]:
        assert shlex.split(res["command"]) == ["nmap", "-p", port, "--script", "ftp-anon", ip]
        assert ip.startswith("192.168.56.") and port.isdigit()
