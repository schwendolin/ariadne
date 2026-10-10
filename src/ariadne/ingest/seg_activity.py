"""Aktivitätsprotokoll: eine Zeile pro lokalem Befehl (Architektur 5.13).

Herkunftsstufe ``local``: Befehl mit gültigem Marker. Ziele kommen aus argv
(:func:`ariadne.scope.targets.analyze_targets`), ohne DNS und ohne Dateien zu
lesen. Die Quell-IP tragen ``net.route``-Ereignisse nach (``ip route get`` beim
C-Marker, sendet kein Paket).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from ariadne.ingest.segmenter import CmdBlock, Layout, UnitPlan
from ariadne.scope.api import ScopeChecker
from ariadne.scope.normalize import to_identifier
from ariadne.scope.targets import analyze_targets, tool_name

__all__ = ["activity_row", "write_activity", "add_route"]

_COLS = (
    "cmd_id", "terminal_id", "ts_utc_ns", "ts_end_ns", "operator_id", "ctx_kind", "ctx_host", "ctx_user",
    "tool", "cmd_text", "targets", "target_files", "target_scope", "scope_version", "exit_code", "evidence",
    "unit_id", "origin",
)


def _main_unit(block: CmdBlock, units: list[UnitPlan]) -> UnitPlan | None:
    for u in units:
        if u.block is block and u.start <= block.c_off < (u.end if u.end is not None else 1 << 62):
            return u
    return next((u for u in units if u.block is block), None)


def activity_row(block: CmdBlock, layout: Layout, scope: ScopeChecker | None) -> dict[str, Any]:
    """Zeile für ``activity``. Kontext ist der Stapel vor dem C-Marker."""
    ctx: Mapping[str, Any] = {}
    for st in block.ctx:
        if st.get("state", "active") == "active":
            ctx = st
    t = analyze_targets(list(block.argv))
    verdicts: list[dict[str, Any]] = []
    for raw in t.targets:
        entry: dict[str, Any] = {"raw": raw, "id": to_identifier(raw)}
        if scope is not None:
            v = scope.check(raw, block.ts_start)
            entry["verdict"], entry["rule"] = v.verdict, v.rule
        verdicts.append(entry)
    unit = _main_unit(block, layout.units)
    end = block.end_off
    evidence = {"t": "stream", "terminal": block.terminal_id, "off": [block.c_off, end],
                "unit": unit.unit_id if unit is not None else None}
    return {
        "cmd_id": block.cmd_id,
        "terminal_id": block.terminal_id,
        "ts_utc_ns": block.ts_start,
        "ts_end_ns": block.ts_end,
        "operator_id": block.operator_id,
        "ctx_kind": ctx.get("kind"),
        "ctx_host": ctx.get("host"),
        "ctx_user": ctx.get("user") or block.user,
        "tool": tool_name(list(block.argv)) or None,
        "cmd_text": block.text,
        "targets": json.dumps(t.targets, ensure_ascii=False),
        "target_files": json.dumps(t.input_files, ensure_ascii=False),
        "target_scope": json.dumps(verdicts, ensure_ascii=False),
        "scope_version": getattr(scope, "version", None) if scope is not None else None,
        "exit_code": block.exit,
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "unit_id": unit.unit_id if unit is not None else None,
        "origin": "local",
    }


def write_activity(conn: Any, row: Mapping[str, Any]) -> None:
    cols = ", ".join(_COLS)
    marks = ", ".join("?" for _ in _COLS)
    updates = ", ".join(f"{c} = excluded.{c}" for c in _COLS if c != "cmd_id")
    conn.execute(f"INSERT INTO activity({cols}) VALUES ({marks}) "  # noqa: S608 - feste Spaltennamen
                 f"ON CONFLICT(cmd_id) DO UPDATE SET {updates}", tuple(row[c] for c in _COLS))
    conn.execute("UPDATE activity SET src_ip = (SELECT src_ip FROM net_route WHERE net_route.cmd_id = "
                 "activity.cmd_id AND src_ip IS NOT NULL ORDER BY seq LIMIT 1) WHERE cmd_id = ?",
                 (row["cmd_id"],))


def add_route(conn: Any, seq: int, header: Mapping[str, Any]) -> None:
    """``net.route`` speichern und die Quell-IP im Protokoll nachtragen."""
    conn.execute("INSERT OR IGNORE INTO net_route(seq, cmd_id, target, src_ip, dev, via) VALUES (?, ?, ?, ?, ?, ?)",
                 (seq, header.get("cmd_id"), header.get("target"), header.get("src_ip"), header.get("dev"),
                  header.get("via")))
    if header.get("src_ip"):
        conn.execute("UPDATE activity SET src_ip = ? WHERE cmd_id = ? AND src_ip IS NULL",
                     (header.get("src_ip"), header.get("cmd_id")))
