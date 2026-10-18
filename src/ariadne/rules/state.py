"""Zustand der Denkanstösse aus den Entscheiden (``docs/web-api.md`` 18.6).

Quelle ist die Tabelle ``decision`` der Projektion (Kopie der Entscheide aus dem Journal); darum
übersteht der Zustand jeden Reparse. Widerrufene Entscheide (``d.revoke``, auch verschachtelt wie in
:mod:`ariadne.ingest.proj_build`) zählen nicht.

* ``d.suggestion.dismiss`` verwirft für immer, auch nach Reparse, Merge und neuem Anlass.
* ``d.suggestion.done`` gilt, solange ``basis`` gleich dem aktuellen Fingerabdruck des Anlasses ist;
  ändert sich der Anlass, ist der Denkanstoss wieder offen. Es zählt der jüngste aktive Entscheid.
* Ein Denkanstoss hat einen Hauptschlüssel und Nebenschlüssel aus den anderen Kennungen seines
  Subjekts (Merge); ein Entscheid auf irgendeinen davon gilt.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Marks", "load_marks", "state_of", "KINDS"]

KINDS = ("d.suggestion.done", "d.suggestion.dismiss")
_LIMIT = 200_000


@dataclass
class Mark:
    dismiss: tuple[int, str] | None = None  # (seq, decision_id) des jüngsten aktiven Verwerfens
    done: list[tuple[int, str, str | None]] = field(default_factory=list)  # (seq, decision_id, basis)


Marks = dict[str, Mark]


def load_marks(conn: Any) -> Marks:
    rows = conn.execute(
        "SELECT seq, id, kind, payload_json FROM decision "
        "WHERE kind IN ('d.suggestion.done', 'd.suggestion.dismiss', 'd.revoke') ORDER BY seq LIMIT ?",
        (_LIMIT,),
    ).fetchall()
    parsed: list[tuple[int, str, str, dict[str, Any]]] = []
    for seq, did, kind, payload in rows:
        try:
            data = json.loads(payload) if isinstance(payload, str) else {}
        except ValueError:
            data = {}
        parsed.append((int(seq), str(did), str(kind), data if isinstance(data, dict) else {}))
    revoked: set[str] = set()
    for _seq, did, kind, data in reversed(parsed):
        if kind == "d.revoke" and did not in revoked and isinstance(data.get("decision_id"), str):
            revoked.add(data["decision_id"])
    marks: Marks = {}
    for seq, did, kind, data in parsed:
        if kind not in KINDS or did in revoked:
            continue
        key = data.get("suggestion_key")
        if not isinstance(key, str):
            continue
        m = marks.setdefault(key, Mark())
        if kind == "d.suggestion.dismiss":
            m.dismiss = (seq, did)
        else:
            basis = data.get("basis")
            m.done.append((seq, did, basis if isinstance(basis, str) else None))
    return marks


def state_of(marks: Marks, keys: Iterable[str], basis: str) -> tuple[str, str | None]:
    """``(state, decision_id)`` für einen Denkanstoss mit diesen Schlüsseln und diesem Anlass."""
    dismiss: tuple[int, str] | None = None
    done: tuple[int, str, str | None] | None = None
    for k in keys:
        m = marks.get(k)
        if m is None:
            continue
        if m.dismiss is not None and (dismiss is None or m.dismiss[0] > dismiss[0]):
            dismiss = m.dismiss
        for d in m.done:
            if done is None or d[0] > done[0]:
                done = d
    if dismiss is not None:
        return "dismissed", dismiss[1]
    if done is not None and done[2] == basis:
        return "done", done[1]
    return "open", None
