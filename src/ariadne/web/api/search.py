"""``GET /p/{pid}/search`` (Volltext über die Ausgabe, ``queries.search``) und
``GET /p/{pid}/files/pending`` (Warteliste, ctl ``show`` mit ``what = pending``),
``docs/web-api.md`` 13.

Treffer zeigen die Zeile so, wie ``/units/{unit_id}/lines`` sie zeigt: bekannte und eigene Secrets
verdeckt, SGR-verdeckter Text verdeckt, im Präsentationsmodus jeder Secret-Bereich.

Die Volltextsuche läuft über die ungeschwärzten Zeilen (E72). Ein Treffer, der nur dank eines eigenen
Secrets zustande kommt, würde verraten, ob ein geratenes Wort ein eigenes Secret ist (SEC-W4). Darum
fallen Treffer weg, deren Zeile nach dem Ersetzen der eigenen Secrets die Suchphrase nicht mehr
enthält (Wörter wie beim Tokenizer ``unicode61``: Buchstaben und Ziffern, Gross-/Kleinschreibung und
Akzente egal).
"""

from __future__ import annotations

import asyncio
import os
import re
import stat
import unicodedata
from typing import Any

from fastapi import APIRouter, Query
from starlette.responses import Response

from ariadne.ingest import queries
from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError
from ariadne.web.api.evidence import render_rows, secret_spans
from ariadne.web.api.text import Bag, iso
from ariadne.web.api.views import with_secrets

__all__ = ["add_routes", "search_view", "own_secret_hit", "PENDING_MAX", "PENDING_REASONS", "pending_reason"]

PENDING_MAX = 200
_WORD = re.compile(r"[^\W_]+")


def _tokens(text: str) -> list[str]:
    """Wörter etwa wie FTS5 ``unicode61`` (ohne Akzente, ohne Gross-/Kleinschreibung)."""
    folded = unicodedata.normalize("NFKD", text.casefold())
    plain = "".join(ch for ch in folded if not unicodedata.combining(ch))
    return _WORD.findall(plain)


def _has_phrase(words: list[str], phrase: list[str]) -> bool:
    if not phrase:
        return False
    n = len(phrase)
    return any(words[i : i + n] == phrase for i in range(len(words) - n + 1))


def own_secret_hit(text: str, q: str, redactor: Any) -> bool:
    """Wahr, wenn die Zeile die Phrase nur mit eigenen Secrets enthält (Treffer verwerfen)."""
    if redactor is None:
        return False
    red, _labels = redactor.redact_for_exit(text)
    if red == text:
        return False
    return not _has_phrase(_tokens(str(red)), _tokens(q))


def search_view(
    conn: Any, q: str, limit: int, *, presentation: bool, redactor: Any, bag: Bag
) -> dict[str, Any]:
    hits = queries.search(conn, q, limit + 1)
    bag = with_secrets(bag, conn)
    secrets = list(bag.known or ())
    spans: dict[str, dict[int, list[tuple[int, int]]]] = {}
    items: list[dict[str, Any]] = []
    for h in hits[:limit]:
        row = conn.execute(
            "SELECT pos, idx, text, flags, sgr FROM unit_line WHERE unit_id = ? AND n = ?",
            (h["unit_id"], h["n"]),
        ).fetchone()
        if row is None or own_secret_hit(str(row[2]), q, redactor):
            continue
        uid = str(h["unit_id"])
        if presentation and uid not in spans:
            spans[uid] = secret_spans(conn, uid)
        line = render_rows([row], secrets, spans.get(uid, {}), reveal=False, redactor=redactor)[0]
        b = bag.new()
        item = {
            "unit_id": uid,
            "line": line["n"],
            "text": line["text"],
            "kind": h.get("kind"),
            "context_label": b(h.get("context")) or "",
            "host_id": b(h.get("host")) if h.get("host") != "local" else None,
            "cmd": b.cmd(h.get("cmd")),
            "ts": iso(h.get("ts")),
        }
        item["ctrl"] = bool(line["ctrl"]) or b.ctrl
        items.append(item)
    return {"items": items, "truncated": len(hits) > limit}


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/search", name="search")
    async def get_search(
        pid: str,
        q: str = Query(..., min_length=1, max_length=200),  # noqa: B008
        limit: int = Query(default=50, ge=1, le=200),
    ) -> Response:  # noqa: B008
        p = api.project(pid)
        bag = api.bag()
        d = api.daemon
        presentation = bool(d.presentation)
        red = d.redactor
        if any(ch < " " or ch == "\x7f" for ch in q):  # NUL und Steuerzeichen: 422, nie 500 (SEC-W5)
            raise ApiError("validation", [{"loc": ["query", "q"], "type": "control_char"}])
        if not q.strip():
            return await api.respond({"items": [], "truncated": False})
        res = await api.query(
            p, lambda c: search_view(c, q, limit, presentation=presentation, redactor=red, bag=bag)
        )
        return await api.respond(res)

    @router.get("/p/{pid}/files/pending", name="files_pending")
    async def get_pending(pid: str) -> Response:
        p = api.project(pid)
        res = await api.call("show", {"what": "pending", "limit": PENDING_MAX})
        api.same(p)
        bag = api.bag()
        raw = list((res or {}).get("items") or [])
        workspace = getattr(p.info, "workspace", None)
        sizes = await asyncio.to_thread(lambda: [_lsize(f.get("path"), workspace) for f in raw])
        api.same(p)
        files = []
        for f, size in zip(raw, sizes, strict=True):
            b = bag.new()
            item = {
                "path": b(f.get("path")) or "",
                "reason": pending_reason(f.get("reason")),
                "cmd_id": f.get("cmd_id"),
                "terminal_id": f.get("terminal_id"),
                "ts": iso(f.get("ts")),
                "size": size,
            }
            item["ctrl"] = b.ctrl
            files.append(item)
        return await api.respond({"files": files, "truncated": len(files) >= PENDING_MAX})


PENDING_REASONS = (
    "outside_workspace",
    "symlink",
    "hardlink",
    "owner",
    "not_regular",
    "other_fs",
    "path",
    "too_large",
)
_REASON_MAP = {"symlink_or_not_dir": "symlink"}


def pending_reason(raw: Any) -> str:
    """Grund als fester Code (18.8); andere Gründe des Daemons (fehlt, keine Rechte, Sperrliste)
    gelten als ``path``."""
    r = _REASON_MAP.get(str(raw), str(raw))
    return r if r in PENDING_REASONS else "path"


def _lsize(path: Any, workspace: Any) -> int | None:
    """Grösse per ``lstat`` (ohne Symlinks zu folgen), sonst ``None``."""
    if not isinstance(path, str) or not path or "\0" in path or len(path) > 4096:
        return None
    try:
        full = path if os.path.isabs(path) or workspace is None else os.path.join(str(workspace), path)
        st = os.lstat(full)
    except (OSError, ValueError):
        return None
    return int(st.st_size) if stat.S_ISREG(st.st_mode) else None
