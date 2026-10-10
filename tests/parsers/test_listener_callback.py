from __future__ import annotations

import pytest

from ariadne.parsers.api import Mention, Obs
from ariadne.parsers.listener_callback import ListenerCallbackParser
from tests.parsers.helpers import make_unit

P = ListenerCallbackParser()
REV = {"kind": "revshell", "opened_at": 100}


def seg(text: str, **kw):
    kw.setdefault("context", REV)
    return make_unit(text, kind="segment", **kw)


def test_contract():
    assert (P.id, P.trust, P.auto_eligible) == ("listener.callback", "tool_text", False)


def test_match():
    assert P.match(seg("x")) == 40
    assert P.match(seg("x", context={"kind": "ssh", "opened_at": 1})) == 0
    assert P.match(make_unit("x", cmd="rlwrap nc -lvnp 4444")) == 40
    assert P.match(make_unit("x", cmd="msfconsole -q")) == 40
    assert P.match(make_unit("x", cmd="curl http://x")) == 0
    assert P.companions(["nc", "-lvnp", "4444"], "/w") == []


@pytest.mark.parametrize(
    "lines,listener,remote",
    [
        (
            ["listening on [any] 9001 ...", "connect to [10.10.14.2] from (UNKNOWN) [10.10.10.3] 40000"],
            "nc:9001",
            "10.10.10.3:40000",
        ),
        (
            ["Ncat: Listening on 0.0.0.0:9001", "Ncat: Connection from 10.10.10.3:40000."],
            "ncat:9001",
            "10.10.10.3:40000",
        ),
        (["Ncat: Connection from 10.10.10.3."], "ncat", "10.10.10.3"),
        (
            ["Listening on 0.0.0.0 9001", "Connection received on 10.10.10.3 40000"],
            "nc:9001",
            "10.10.10.3:40000",
        ),
        (["[12:00:01] received connection from 10.10.10.3:40000   bind.py:84"], "pwncat", "10.10.10.3:40000"),
        (
            ["[*] Command shell session 3 opened (10.10.14.2:9001 -> 10.10.10.3:40000) at 2026-10-08"],
            "msf:9001",
            "10.10.10.3:40000",
        ),
        (["Ncat: Connection from ::ffff:10.10.10.3:40000."], "ncat", "::ffff:10.10.10.3:40000"),
    ],
)
def test_formats(lines, listener, remote):
    items = list(P.parse(seg("\n".join(lines))))
    obs = [o for o in items if isinstance(o, Obs)]
    assert len(obs) == 1, items
    o = obs[0]
    assert o.predicate == "access.callback" and o.subject.key == "ip:default/10.10.10.3"
    assert o.value == listener
    assert o.attrs["remote"] == remote


def test_port_from_argv():
    items = list(
        P.parse(make_unit("connect to [10.10.14.2] from (UNKNOWN) [10.10.10.3] 40000", cmd="nc -lvnp 9443"))
    )
    assert [o.value for o in items if isinstance(o, Obs)] == ["nc:9443"]
    items = list(
        P.parse(make_unit("[1] received connection from 10.10.10.3:40000", cmd="pwncat-cs -lp 9999"))
    )
    assert [o.value for o in items if isinstance(o, Obs)] == ["pwncat:9999"]


def test_only_first_hit_counts():
    text = "\n".join(
        [
            "listening on [any] 4444 ...",
            "connect to [10.10.14.2] from (UNKNOWN) [10.10.10.3] 40000",
            "connect to [10.10.14.2] from (UNKNOWN) [10.66.66.66] 31337",
            "[*] Meterpreter session 9 opened (10.10.14.2:4444 -> 10.66.66.66:31337) at x",
        ]
    )
    items = list(P.parse(seg(text)))
    assert [o.subject.key for o in items if isinstance(o, Obs)] == ["ip:default/10.10.10.3"]
    fakes = [m for m in items if isinstance(m, Mention)]
    assert [m.value_type for m in fakes] == ["callback", "callback"]
    assert {m.attrs["reason"] for m in fakes} <= {"not_first", "after_output"}


def test_callback_after_target_output_is_only_a_mention():
    text = "uid=33(www-data)\nconnect to [10.10.14.2] from (UNKNOWN) [10.66.66.66] 31337\n"
    items = list(P.parse(seg(text)))
    assert not [o for o in items if isinstance(o, Obs)]
    assert items[0].attrs["reason"] == "after_output"


def test_msf_first_session_counts_even_after_module_output():
    text = "\n".join(
        [
            "[*] Started reverse TCP handler on 10.10.14.2:4444",
            "[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)",
            "[*] Command shell session 1 opened (10.10.14.2:4444 -> 10.10.10.3:6200) at x",
            "[*] Command shell session 2 opened (10.10.14.2:4444 -> 10.10.10.9:6200) at x",
        ]
    )
    items = list(P.parse(seg(text, context={"kind": "msf", "opened_at": 5})))
    obs = [o for o in items if isinstance(o, Obs)]
    assert [(o.subject.key, o.value, o.attrs["session"]) for o in obs] == [
        ("ip:default/10.10.10.3", "msf:4444", "1")
    ]


def test_hostname_peer_is_mention_only():
    items = list(P.parse(seg("Connection received on lame.htb 40000")))
    assert not [o for o in items if isinstance(o, Obs)]
    assert items and items[0].value == "lame.htb:40000"


def test_late_listening_line_does_not_change_port():
    text = (
        "listening on [any] 4444 ...\nconnect to [a] from (UNKNOWN) [10.10.10.3] 1\n"
        "listening on [any] 9999 ...\nconnect to [a] from (UNKNOWN) [10.10.10.4] 2\n"
    )
    items = list(P.parse(seg(text)))
    assert [o.value for o in items if isinstance(o, Obs)] == ["nc:4444"]
