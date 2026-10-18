"""SEC4-SHOT-1: Fenstertitel und Notiz eines Screenshots sind Zieldaten. Bekannte Secret-Werte vom
Ziel (``secret_value``) erscheinen dort maskiert, wie in Suche und Belegen (E99): Web-Liste und
``ariadne shot``. Fixtures ``paths`` und ``operator`` aus ``tests/screenshots/conftest.py``."""

from __future__ import annotations

from typing import Any

from tests.web.api.helpers import CRYPT, run_api, sync


def test_shot_title_and_note_mask_known_secret_values(paths: Any, operator: Any, monkeypatch: Any) -> None:
    from ariadne.sources import screenshot as shot
    from ariadne.sources import screenshot_service as svc

    png = shot.encode_png(b"\x10\x20\x30" * 4, 2, 2)

    async def fake_capture(env: Any, mode: str, reg: Any) -> shot.Capture:
        return shot.Capture(png=png, mode="window", width=2, height=2, dhash=None,
                            window_title=f"[REC lame] | root@ms2: echo {CRYPT}", wm_class="xfce4-terminal")

    monkeypatch.setattr(svc, "CAPTURE", fake_capture)

    async def body(d: Any, c: Any, fx: Any, bus: Any, ctx: Any) -> None:
        await sync(d)
        known = await (await d._sync_ingest()).query(
            lambda conn: [r[0] for r in conn.execute("SELECT value FROM secret_value")])
        assert CRYPT in known  # Voraussetzung: der Wert ist als Secret vom Ziel bekannt
        res = await d.call("shot.take", {"mode": "window", "display": {"DISPLAY": ":0"},
                                         "note": f"Hash {CRYPT} gefunden"})
        assert res["ok"], res
        cli = res["result"]
        assert CRYPT not in str(cli) and "root@ms2" in cli["window_title"] and "Hash" in cli["note"]
        r = await c.get(f"/api/v1/p/{fx.pid}/screenshots")
        assert r.status_code == 200
        (item,) = r.json()["items"]
        assert CRYPT not in r.text
        assert "root@ms2: echo" in item["window_title"] and item["note"].startswith("Hash ")

    run_api(paths, operator, body)
