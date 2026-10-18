"""Bausteine der API ohne Daemon: sichtbare Steuerzeichen und ``ctrl``, Logzeilen mit verdeckten
Bereichen, Zeit, Cursor, Fehlerformat (feste Texte, 422 ohne Werte), Routen-Klasse, Service-Klassen,
Anfrage-Modelle."""

from __future__ import annotations

import asyncio
import json
import math

import httpx
import pytest
from fastapi import APIRouter, FastAPI
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from ariadne.web.api import errors, models
from ariadne.web.api.common import ALLOWED_OPS, Api
from ariadne.web.api.errors import ApiError, ApiRoute, from_ctl, validation_detail
from ariadne.web.api.graph import service_class
from ariadne.web.api.text import (
    MASK,
    Bag,
    decode_cursor,
    deep_visible,
    encode_cursor,
    iso,
    ns_str,
    render_line,
    visible_text,
)

CONTROL = [chr(c) for c in range(0x20)] + ["\x7f"] + [chr(c) for c in range(0x80, 0xA0)]
BIDI = [
    "\u202e",
    "\u202d",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
    "\u200b",
    "\u200e",
    "\u200f",
    "\ufeff",
    "\u2028",
    "\u2029",
    "\U000e0041",
]


def _clean(s: str) -> bool:
    return not any(ch in s for ch in CONTROL + BIDI)


def test_visible_text_shows_controls_bidi_and_separators():
    assert visible_text("a\x1b[31mb\x07") == "a<ESC>[31mb<BEL>"
    assert visible_text("evil\u202etxt.exe") == "evil<U+202E>txt.exe"
    assert visible_text("x\u2028y\u2029z") == "x<U+2028>y<U+2029>z"
    assert visible_text("<script>alert(1)</script>") == "<script>alert(1)</script>"  # Text bleibt Text
    assert visible_text(MASK) == MASK


@given(st.text())
def test_visible_text_never_leaves_controls_and_is_idempotent(s):
    out = visible_text(s)
    assert _clean(out)
    assert visible_text(out) == out


def test_bag_sets_ctrl_and_redacts_before_escaping():
    class Red:
        def redact_for_exit(self, s):
            return s.replace("Geheim", "******"), ["x"] if "Geheim" in s else []

    b = Bag(Red())
    assert b("harmlos") == "harmlos" and b.ctrl is False
    assert b("Geheim\x1b") == "******<ESC>" and b.ctrl is True
    assert b(None) is None
    assert b.many(["a", None, 3]) == ["a", "3"]
    assert b.new().ctrl is False


def test_bag_cmd_masks_known_secrets_and_refuses_without_list():
    """SEC-W1: Befehlstexte nur mit geladener Secret-Liste, bekannte Werte ohne Längenangabe."""
    from ariadne.web.api.text import MissingSecrets, mask_known

    with pytest.raises(MissingSecrets):
        Bag().cmd("crackmapexec -H 8846f7eaee8fb117ad06bdd830b7586c")
    b = Bag(presentation=True).with_known(["8846f7ea", "8846f7eaee8fb117ad06bdd830b7586c"])
    assert b.presentation and b.new().known == b.known
    assert b.cmd("cme -H 8846f7eaee8fb117ad06bdd830b7586c x") == f"cme -H {MASK} x"
    assert b.cmd(None) is None and mask_known("abc", ["b"]) == f"a{MASK}c"


def test_prompt_secret_texts_and_with_secrets_in_presentation():
    """Im Präsentationsmodus verdecken Secret-Bereiche aus Prompt-Zeilen auch den Befehlstext."""
    import sqlite3

    from ariadne.web.api.views import prompt_secret_texts, secret_values, with_secrets

    conn = sqlite3.connect(":memory:")
    conn.executescript(
        "CREATE TABLE secret_value (secret_ident, kind, value);"
        "CREATE TABLE observation (unit_id, span_json, is_secret);"
        "CREATE TABLE mention (unit_id, span_json, is_secret);"
        "CREATE TABLE unit_line (unit_id, idx, text, flags);"
    )
    conn.execute("INSERT INTO secret_value VALUES ('s1', 'hash', 'aad3b435b51404ee'), ('s2', 'x', 'abc')")
    line = "kali$ cme smb 10.0.0.1 -H 8846f7eaee8fb117ad06bdd830b7586c"
    col = line.index("8846")
    conn.execute(
        "INSERT INTO mention VALUES ('u1', ?, 1)",
        (json.dumps({"line_start": 0, "line_end": 0, "col_start": col, "col_end": col + 32}),),
    )
    conn.execute("INSERT INTO mention VALUES ('u1', ?, 0)", (json.dumps({"line_start": 0, "line_end": 0}),))
    conn.execute("INSERT INTO unit_line VALUES ('u1', 0, ?, 1)", (line,))
    conn.execute("INSERT INTO unit_line VALUES ('u1', 1, 'ausgabe 8846f7eaee8fb117ad06bdd830b7586c', 0)")
    assert secret_values(conn) == ["aad3b435b51404ee"]  # kürzer als 4 Zeichen zählt nicht
    assert prompt_secret_texts(conn) == ["8846f7eaee8fb117ad06bdd830b7586c"]
    cmd = "cme smb 10.0.0.1 -H 8846f7eaee8fb117ad06bdd830b7586c"
    assert with_secrets(Bag(), conn).cmd(cmd) == cmd  # ohne Präsentationsmodus: nur secret_value
    assert with_secrets(Bag(presentation=True), conn).cmd(cmd) == f"cme smb 10.0.0.1 -H {MASK}"


def test_deep_visible_reaches_keys_and_nested_values():
    out = deep_visible({"k\x1b": ["v\u202e", {"x": "\x07"}], "n": 1, "t": None})
    assert out == {"k<ESC>": ["v<U+202E>", {"x": "<BEL>"}], "n": 1, "t": None}


def test_render_line_masks_and_remaps_columns():
    text = "pw=Geheim1234 \x1b ok"
    sgr = [
        {"s": 0, "e": 2, "fg": "red"},
        {"s": 14, "e": 15, "fg": "blue", "b": 1},
        {"s": 16, "e": 18, "c": 1},
    ]
    shown, ctrl, masked, spans = render_line(text, [(3, 13, "secret"), (16, 18, "concealed")], sgr)
    assert shown == f"pw={MASK} <ESC> {MASK}" and ctrl is True
    assert masked == [
        {"col_start": 3, "col_end": 11, "kind": "secret"},
        {"col_start": 18, "col_end": 26, "kind": "concealed"},
    ]
    assert spans[0] == {"col_start": 0, "col_end": 2, "fg": "red", "bg": None, "bold": False}
    assert shown[spans[1]["col_start"] : spans[1]["col_end"]] == "<ESC>" and spans[1]["bold"] is True
    # überlappende Bereiche werden zusammengeführt, Bereiche ausserhalb ignoriert
    shown, _, masked, _ = render_line("abcdef", [(1, 3, "a"), (2, 5, "b"), (10, 12, "x"), (4, 2, "y")])
    assert shown == f"a{MASK}f" and len(masked) == 1


@given(st.text(max_size=60), st.lists(st.tuples(st.integers(0, 70), st.integers(0, 70)), max_size=4))
def test_render_line_never_shows_masked_text_or_controls(text, ranges):
    masks = [(a, b, "secret") for a, b in ranges]
    shown, _, masked, _ = render_line(text, masks)
    assert _clean(shown)
    for m in masked:
        assert shown[m["col_start"] : m["col_end"]] == MASK


def test_iso_and_ns_str():
    assert iso(1_792_000_000_123_456_789) == "2026-10-14T17:46:40.123456Z"
    assert iso(None) is None and iso(0) is None and iso(True) is None and iso(10**40) is None
    assert ns_str(1_792_000_000_123_456_789) == "1792000000123456789" and ns_str("1") is None


def test_cursor_roundtrip_and_rejects_garbage():
    c = encode_cursor({"id": "u:x@1", "ts": 5})
    assert decode_cursor(c) == {"id": "u:x@1", "ts": 5} and decode_cursor(None) is None
    for bad in ("!!!", "W10", "x" * 600):
        with pytest.raises(ValueError):
            decode_cursor(bad)


def test_error_format_fixed_texts_and_ctl_mapping():
    for code, status in errors.STATUS.items():
        r = errors.error_response(code)
        body = json.loads(r.body)
        assert r.status_code == status and body == {"error": {"code": code, "message": errors.MESSAGES[code]}}
        assert r.headers["content-type"] == "application/json; charset=utf-8"
    assert errors.MESSAGES["not_implemented"] == "Kommt in einer späteren Version."
    mapping = {
        "locked": 423,
        "no_project": 409,
        "not_found": 404,
        "unknown_terminal": 404,
        "invalid": 422,
        "policy": 403,
        "conflict": 409,
        "project_changed": 409,
        "no_ingest": 503,
        "vault": 500,
        "guardrail": 403,  # E129: Scope-Änderung ausserhalb der Lab-Allowlist (web-api.md 20.2)
        None: 500,
    }
    for code, status in mapping.items():
        e = from_ctl({"code": code, "message": "Zieldaten <script>"})
        assert errors.STATUS[e.code] == status
    assert ApiError("gibt es nicht").code == "internal"


def test_validation_detail_never_contains_values():
    class M(BaseModel):
        model_config = {"extra": "forbid"}
        a: int

    with pytest.raises(ValidationError) as exc:
        M.model_validate({"a": "<script>geheim</script>", "b\x1b": "Sudo-Geheim-4711"})
    detail = validation_detail(exc.value.errors())
    text = json.dumps(detail)
    assert "geheim" not in text.lower() and "\x1b" not in text and "<ESC>" in text
    assert all(set(d) == {"loc", "type"} for d in detail)


def _route_app() -> FastAPI:
    app = FastAPI()
    router = APIRouter(route_class=ApiRoute)

    async def fails() -> None:
        raise RuntimeError("Zieldaten <script>alert(1)</script> Sudo-Geheim-4711")

    async def api_error() -> None:
        raise ApiError("policy")

    async def typed(n: int, body: models.PauseRequest) -> dict:
        return {"n": n}

    router.add_api_route("/fails", fails, methods=["GET"])
    router.add_api_route("/policy", api_error, methods=["GET"])
    router.add_api_route("/typed", typed, methods=["POST"])
    app.include_router(router)
    return app


def test_api_route_formats_own_errors_without_exception_text():
    async def main() -> None:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=_route_app()), base_url="http://t"
        ) as c:
            r = await c.get("/fails")
            assert r.status_code == 500 and r.json() == {
                "error": {"code": "internal", "message": "Interner Fehler."}
            }
            assert "script" not in r.text and "Geheim" not in r.text
            r = await c.get("/policy")
            assert r.status_code == 403 and r.json()["error"]["code"] == "policy"
            r = await c.post("/typed?n=x", json={"minutes": "Sudo-Geheim-4711", "zz": 1})
            assert r.status_code == 422 and r.json()["error"]["code"] == "validation"
            assert "Geheim" not in r.text and {tuple(d["loc"])[:1] for d in r.json()["error"]["detail"]} <= {
                ("query",),
                ("body",),
            }

    asyncio.run(main())


def test_request_models_are_strict_and_forbid_extra():
    with pytest.raises(ValidationError):
        models.PauseRequest.model_validate_json('{"minutes": "10"}')
    with pytest.raises(ValidationError):
        models.PauseRequest.model_validate_json('{"minutes": 10, "x": 1}')
    with pytest.raises(ValidationError):
        models.PresentationRequest.model_validate_json('{"on": 1}')
    assert models.PauseRequest.model_validate_json('{"minutes": 30}').minutes == 30
    with pytest.raises(ValidationError):
        models.Position.model_validate_json('{"x": NaN, "y": 1}')
    for raw in ('{"x": 1e400, "y": 1}', '{"x": 1, "y": 1, "z": 2}'):
        with pytest.raises(ValidationError):
            models.Position.model_validate_json(raw)
    p = models.Position.model_validate_json('{"x": 1, "y": 2.5}')
    assert math.isfinite(p.x) and p.y == 2.5
    with pytest.raises(ValidationError):
        models.ConfirmGroupRequest.model_validate_json('{"group_ref": "G1234567"}')
    with pytest.raises(ValidationError):
        models.DecisionRequest.model_validate_json('{"decisions": []}')


def test_service_classes():
    cases = {
        ("http", 8080): "web",
        ("ssl/http", 443): "web",
        ("microsoft-ds", 445): "smb",
        ("netbios-ssn", 139): "smb",
        ("mysql", 3306): "db",
        ("ssh", 22): "remote",
        ("ftp", 21): "file",
        ("smtp", 25): "mail",
        ("domain", 53): "other",
        (None, 3389): "remote",
        ("x-unknown", 1): "other",
        ("<script>", 99999): "other",
    }
    for (name, port), cls in cases.items():
        assert service_class(name, port) == cls


def test_api_call_refuses_ops_outside_the_contract():
    class D:
        async def call(self, op, args):  # pragma: no cover - darf nie erreicht werden
            raise AssertionError(op)

    api = Api.__new__(Api)
    api.ctx = type("C", (), {"daemon": D()})()
    for op in (
        "unlock",
        "start",
        "lock",
        "stop",
        "shutdown",
        "secrets.add",
        "redact",
        "import",
        "project.open",
        "reparse",
        "verify",
        "ui.code",
        "init",
    ):
        assert op not in ALLOWED_OPS
        with pytest.raises(RuntimeError):
            asyncio.run(api.call(op, {}))
