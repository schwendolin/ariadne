"""Szenarien für die Regel-Tests: echte Projektionen aus den Lab-Ausgaben (MS2, Lame) und ein Host
mit feindlichen Bannern. Zeiten wie im Design (Scan 14:02 Lokalzeit am 2026-10-08)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ariadne.parsers.api import Obs, Ref, Span
from ariadne.rules import api as rules_api
from ariadne.store.api import EventRecord
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, dec, feed, new_projector

TESTS = Path(__file__).parents[1]
KALI = "192.168.56.102"
MS2 = "192.168.56.101"
LAME = "10.10.10.3"
CMD = "0199a2b3-0000-7000-8000-000000000001@120"
T0 = int(datetime(2026, 10, 8, 12, 2, 11, tzinfo=UTC).timestamp()) * 10**9  # 14:02:11 CEST

# Feindliche Produkte (A 6.1 Punkt 4): Anführungszeichen mit Shell, Befehlsersetzung, Backticks,
# Zeilenumbruch, Bidi, ESC, Homoglyph (kyrillisches «р»). Harmlos, falls je ausgeführt.
HOSTILE_PRODUCTS: dict[int, tuple[str, str]] = {
    21: ("ftp", "vsftpd'; !sh -c 'id"),
    2121: ("ftp", "ProFTPD $(echo PWNED)"),
    80: ("http", "Apache`echo PWNED`"),
    3306: ("mysql", "MySQL\nINJECTED"),
    8180: ("http", "Apache Tomcat\u202e/Coyote"),
    8080: ("http", "nginx\x1b[2J"),
    10021: ("ftp", "vsftрd"),
}
HOSTILE = "192.168.56.105"


def ms2_text(*, scripts: bool = True) -> str:
    text = (TESTS / "golden" / "nmap.text" / "ms2_sv_sc" / "input.txt").read_text()
    if scripts:
        return text
    # nmap -sV ohne Skripte: NSE-Zeilen («|…») und den Block «Host script results» weglassen
    out = []
    for line in text.split("\n"):
        if line.startswith("|") or line.startswith("Host script results"):
            continue
        out.append(line)
    return "\n".join(out)


def ms2(
    *,
    scripts: bool = True,
    profile: str = "lab",
    decisions: Iterable[EventRecord] = (),
    extra: Iterable[tuple[str, str, Iterable[Obs]]] = (),
) -> tuple[Any, Any]:
    """MS2 wie ``tests/projection/test_ausw_golden._ms2`` (Kali als eigene Adresse); ``scripts=False``
    ist der Fall aus dem Design (``nmap -sV`` ohne Skripte, ohne XML). ``extra``: weitere Befehle als
    (Befehl, unit_id, Beobachtungen)."""
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]), profile=profile, own=[KALI])
    if scripts:
        xml = (TESTS / "golden" / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes()
        feed(
            p,
            make_unit(ms2_text(), cmd=f"nmap -sV -sC -oA scans/ms2 {MS2}", unit_id="cmd1", ts=T0, cmd_id=CMD),
            journal_seq=10,
        )
        feed(
            p,
            make_unit(
                kind="file",
                data=xml,
                path="scans/ms2.xml",
                sniff="xml:nmaprun",
                unit_id="f:ev1",
                ts=T0 + 10**9,
                cmd_id=CMD,
            ),
            journal_seq=20,
        )
    else:
        feed(
            p,
            make_unit(ms2_text(scripts=False), cmd=f"nmap -sV {MS2}", unit_id="cmd1", ts=T0, cmd_id=CMD),
            journal_seq=10,
        )
    add_commands(p, extra, seq=30)
    for d in decisions:
        p.apply_decision(d)
    p.rebuild()
    return conn, p


def add_commands(p: Any, extra: Iterable[tuple[str, str, Iterable[Obs]]], *, seq: int) -> None:
    for i, (cmd, uid, items) in enumerate(extra):
        apply_items(
            p,
            make_unit("x", cmd=cmd, unit_id=uid, ts=T0 + (i + 5) * 60 * 10**9, cmd_id=f"t@{seq + i}"),
            list(items),
            journal_seq=seq + i,
            parser_id="test.cmd",
        )


def lame(*, profile: str = "lab") -> tuple[Any, Any]:
    conn, p = new_projector(FakeScope(nets=["10.10.10.3/32"]), profile=profile, own=["10.10.14.5"])
    txt = (TESTS / "fixtures" / "lame" / "nmap_sv_sc.txt").read_text()
    t = int(datetime(2026, 10, 15, 17, 2, 0, tzinfo=UTC).timestamp()) * 10**9
    feed(p, make_unit(txt, cmd=f"nmap -sV -sC {LAME}", unit_id="cmd1", ts=t, cmd_id="t@5"), journal_seq=10)
    p.rebuild()
    return conn, p


def hostile(*, profile: str = "lab") -> tuple[Any, Any]:
    """Ein Host mit feindlichen Bannern (nmap -sV ohne Skripte)."""
    conn, p = new_projector(FakeScope(nets=["192.168.56.0/24"]), profile=profile, own=[KALI])
    h = Ref.ip(HOSTILE)
    items: list[Obs] = [Obs(h, "host.state", "up", Span(2, 2))]
    for i, (port, (name, product)) in enumerate(sorted(HOSTILE_PRODUCTS.items())):
        s = Ref.service(h, "tcp", port)
        sp = Span(5 + i, 5 + i)
        items += [
            Obs(s, "service.state", "open", sp),
            Obs(s, "service.name", name, sp),
            Obs(s, "service.product", product, sp),
            Obs(s, "service.version", "2.3.4", sp),
        ]
    apply_items(
        p,
        make_unit("x", cmd=f"nmap -sV {HOSTILE}", unit_id="cmd1", ts=T0, cmd_id="t@1"),
        items,
        parser_id="nmap.text",
    )
    p.rebuild()
    return conn, p


def suggestions(conn: Any, *, state: str = "open", profile: str = "lab", limit: int = 200) -> list[dict]:
    items, _truncated = rules_api.suggestions(conn, profile=profile, state=state, limit=limit)  # type: ignore[arg-type]
    return items


def by_rule(items: list[dict], rule_id: str) -> list[dict]:
    return [s for s in items if s["rule_id"] == rule_id]


def summary(items: list[dict]) -> list[tuple[str, str, list[str | None]]]:
    """(Regel, Titel, Befehle) je Denkanstoss: die lesbare Kurzform für die Golden-Tests. Bei einer Liste
    (E119) die Befehle aller Einträge."""
    return [
        (
            s["rule_id"],
            s["title"],
            [i["template"]["command"] for i in s["items"]]
            if s["items"]
            else [t["command"] for t in s["templates"]],
        )
        for s in items
    ]


def decide(p: Any, seq: int, kind: str, **header: Any) -> None:
    p.apply_decision(dec(seq, kind, **header))
    p.rebuild()
