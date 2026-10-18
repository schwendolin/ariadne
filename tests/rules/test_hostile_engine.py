"""Feindliche Werte durch die ganze Engine (Projektion bis JSON, Hypothesis): Jede gerenderte Vorlage
zerfällt mit ``shlex.split`` in genau die erwarteten Wörter, enthält nur Zeichen ohne Bedeutung für die
Shell, und kein String der Ausgabe enthält ein unsichtbares Steuer-, Bidi- oder Zero-Width-Zeichen."""

from __future__ import annotations

import re
import shlex

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ariadne.parsers.api import Obs, Ref, Span
from ariadne.rules.encoders import SHELL_META
from tests.parsers.helpers import make_unit
from tests.projection import helpers as projection_helpers
from tests.projection.helpers import FakeScope, apply_items, new_projector
from tests.rules import helpers as H
from tests.rules.test_golden import _expected_argv

_ALPHABET = st.sampled_from(
    list("abcXYZ019._+-/:")
    + [" "] * 4
    + sorted(SHELL_META)
    + [
        "\n",
        "\r",
        "\x1b",
        "\x07",
        "\x00",
        "\x7f",
        "\x9b",
        "\u202e",
        "\u200b",
        "\u2028",
        "\ufeff",
        "р",
        "ü",
        "•",
    ]
)
_INVISIBLE = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2028\u2029\u2066-\u2069\ufeff]")
_INERT = re.compile(r"[A-Za-z0-9._:/@=%+ '-]*")


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for k, v in obj.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
    derandomize=True,
    database=None,
)
@given(
    product=st.text(_ALPHABET, min_size=1, max_size=24),
    version=st.text(_ALPHABET, min_size=1, max_size=10),
    name=st.sampled_from(["ftp", "http", "mysql", "netbios-ssn", "smtp", "vnc", "x\x1bftp", "ht'tp"]),
)
def test_property_engine_output_is_inert(product, version, name):
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]), own=[H.KALI])
    try:
        h = Ref.ip("192.168.56.120")
        sp = Span(0, 0)
        s = Ref.service(h, "tcp", 4444)
        items = [
            Obs(h, "host.state", "up", sp),
            Obs(s, "service.state", "open", sp),
            Obs(s, "service.name", name, sp),
            Obs(s, "service.product", product, sp),
            Obs(s, "service.version", version, sp),
        ]
        apply_items(p, make_unit("x", cmd="nmap -sV 192.168.56.120", unit_id="u1", ts=H.T0), items)
        p.rebuild()
        out = H.suggestions(conn, state="all")
        # gespeicherte Werte (die Projektion normalisiert z. B. ein CR am Zeilenende weg)
        stored = dict(
            conn.execute(
                "SELECT predicate, value_text FROM claim WHERE predicate IN ('service.product', "
                "'service.version') AND state IN ('auto','confirmed') AND history = 0"
            ).fetchall()
        )
    finally:
        projection_helpers.OPEN.remove(conn)
        conn.close()
    assert any(x["rule_id"] == "R-FULL-PORTSCAN" for x in out)
    for text in _strings(out):
        assert not _INVISIBLE.search(text), repr(text)
    for sg in out:
        for t in sg["templates"]:
            if not t["rendered"]:
                assert t["command"] is None and t["parts"] == [] and t["blocked_reason"]
                continue
            cmd = t["command"]
            assert _INERT.fullmatch(cmd) and not cmd.endswith("\n"), cmd
            assert shlex.split(cmd) == _expected_argv(t), cmd
        if sg["rule_id"] == "R-VERSION-RECHERCHE":
            (t,) = sg["templates"]
            raw = stored.get("service.product", "") + stored.get("service.version", "")
            bad = "\n\r\x1b\x07\x00\x7f\x9b\u202e\u200b\u2028\ufeff"
            if any(ch in SHELL_META or ch in bad for ch in raw):
                assert not t["rendered"]
