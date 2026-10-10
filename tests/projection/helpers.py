"""Hilfen für Projektionstests: Fake-Scope, Entscheide, Einspeisen von Parsern."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Iterable
from typing import Any

from ariadne.events import validate_header
from ariadne.ingest.projection import Projector
from ariadne.parsers.api import Mention, Obs
from ariadne.parsers.registry import default_registry
from ariadne.scope.api import Verdict
from ariadne.store.api import EventRecord

PROJECT_KEY = b"\x01" * 32


class FakeScope:
    """Scope über Netze und Namen; ``excluded`` schlägt alles, sonst ``out``/``unknown``."""

    def __init__(
        self,
        nets: Iterable[str] = ("192.168.56.0/24",),
        names: Iterable[str] = (),
        excluded: Iterable[str] = (),
        version: int = 1,
    ) -> None:
        self.nets = [ipaddress.ip_network(n) for n in nets]
        self.names = set(names)
        self.excluded = {ipaddress.ip_address(a) for a in excluded}
        self.version = version
        self.calls: list[str] = []

    def check(self, identifier: str, at_utc_ns: int | None = None) -> Verdict:
        self.calls.append(identifier)
        t, _, rest = identifier.partition(":")
        if t == "svc":
            identifier = rest.rpartition("|")[0]
            t, _, rest = identifier.partition(":")
        if t == "ip":
            addr = ipaddress.ip_address(rest.split("/", 1)[1])
            if addr in self.excluded:
                return Verdict("excluded", f"exclude:{addr}", self.version)
            for n in self.nets:
                if addr in n:
                    return Verdict("in", f"include:{n}", self.version)
            return Verdict("out", None, self.version)
        if t == "fqdn":
            return Verdict("in" if rest in self.names else "out", None, self.version)
        return Verdict("unknown", None, self.version)


OPEN: list[sqlite3.Connection] = []  # schliesst tests/projection/conftest.py nach jedem Test


def new_projector(scope: FakeScope | None = None) -> tuple[sqlite3.Connection, Projector]:
    conn = sqlite3.connect(":memory:")
    OPEN.append(conn)
    return conn, Projector(conn, project_key=PROJECT_KEY, scope=scope or FakeScope())


def dec(seq: int, kind: str, ts: int | None = None, did: str | None = None, **header: Any) -> EventRecord:
    hdr = validate_header(kind, header)
    return EventRecord(
        seq=seq,
        id=did or f"dec-{seq}",
        layer="decision",
        kind=kind,
        ts_utc_ns=ts if ts is not None else seq * 1000,
        mono_ns=None,
        boot_id=None,
        operator_id="op",
        origin="webui",
        terminal_id=None,
        stream_off=None,
        header=hdr,
        body=None,
    )


def feed(p: Projector, unit: Any, *, journal_seq: int, parsers: Iterable[Any] | None = None) -> int:
    """Lässt alle passenden Parser laufen und gibt die Ergebnisse an die Projektion."""
    n = 0
    for parser in parsers if parsers is not None else default_registry():
        if parser.match(unit) <= 0:
            continue
        n += p.apply_unit(
            unit,
            parser_id=parser.id,
            parser_version=parser.version,
            trust=parser.trust,
            auto_eligible=parser.auto_eligible,
            journal_seq=journal_seq,
            items=list(parser.parse(unit)),
        )
    return n


def apply_items(
    p: Projector,
    unit: Any,
    items: Iterable[Obs | Mention | dict],
    *,
    journal_seq: int = 10,
    parser_id: str = "test.parser",
    trust: str = "structured",
    auto_eligible: bool = True,
) -> int:
    return p.apply_unit(
        unit,
        parser_id=parser_id,
        parser_version="1",
        trust=trust,
        auto_eligible=auto_eligible,
        journal_seq=journal_seq,
        items=items,
    )


def rows(conn: sqlite3.Connection, sql: str, *args: Any) -> list[tuple]:
    return [tuple(r) for r in conn.execute(sql, args)]


def claims(conn: sqlite3.Connection, predicate: str | None = None) -> dict[tuple[str, str, str], dict]:
    """Claims als {(subject, predicate, value_text): Zeile als Dict}."""
    cur = conn.execute("SELECT * FROM claim")
    names = [d[0] for d in cur.description]
    out = {}
    for r in cur:
        d = dict(zip(names, r, strict=True))
        if predicate is None or d["predicate"] == predicate:
            out[(d["subject_identifier"], d["predicate"], d["value_text"])] = d
    return out


def inbox(conn: sqlite3.Connection, kind: str | None = None) -> list[dict]:
    out = []
    for r in conn.execute(
        "SELECT item_key, kind, group_key, title, payload_json FROM v_inbox ORDER BY item_key"
    ):
        if kind is None or r[1] == kind:
            out.append({"key": r[0], "kind": r[1], "group": r[2], "title": r[3], "payload": json.loads(r[4])})
    return out


def entity(conn: sqlite3.Connection, eid: str) -> dict | None:
    cur = conn.execute("SELECT * FROM entity WHERE entity_id = ?", (eid,))
    names = [d[0] for d in cur.description]
    r = cur.fetchone()
    return dict(zip(names, r, strict=True)) if r else None
