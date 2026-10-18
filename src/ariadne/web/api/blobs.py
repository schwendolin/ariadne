"""``GET /p/{pid}/blobs/{blob_id}``: ein Bild aus dem Blob-Store als Bytes (Bau v0.1-Screenshots).

Ausgeliefert wird nur, was Ariadne selbst als Screenshot abgelegt hat (``kind = "screenshot"``:
kanonisches PNG, neu kodiert, ohne Metadaten) und nur, wenn die Bytes nach Magic-Bytes PNG, JPEG
oder WebP sind; ein PNG muss zusätzlich kanonisch sein (nur IHDR, IDAT, IEND). Nie SVG, nie HTML,
nie andere Dateien aus dem Ziel: alles andere ist 404, ohne zu verraten, ob es den Blob gibt.

Kopfzeilen: ``Content-Type`` aus der Prüfung, ``Content-Disposition: inline`` mit festem Namen;
``X-Content-Type-Options: nosniff``, ``Cache-Control: no-store`` und ``CSP: ... sandbox`` setzt die
Sicherheitsschicht des Servers für jede Antwort. Im Präsentationsmodus 403 ``policy``.

Besitzer: Teil «screenshots» (Bau v0.1-Screenshots).
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from starlette.responses import Response

from ariadne.web.api.common import Api
from ariadne.web.api.errors import ApiError

__all__ = ["add_routes", "ALLOWED_MIME"]

ALLOWED_MIME = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}


def _valid_blob_id(blob_id: str) -> bool:
    try:
        return str(uuid.UUID(blob_id)) == blob_id
    except (ValueError, TypeError, AttributeError):
        return False


def add_routes(router: APIRouter, api: Api) -> None:
    @router.get("/p/{pid}/blobs/{blob_id}", name="blob")
    async def blob(pid: str, blob_id: str) -> Response:
        from ariadne.sources.screenshot import check_png, sniff_image
        from ariadne.sources.screenshot_service import is_screenshot_blob

        p = api.project(pid)
        if api.daemon.presentation:
            raise ApiError("policy")
        if not _valid_blob_id(blob_id) or not is_screenshot_blob(p, blob_id):
            raise ApiError("not_found")
        try:
            data = p.blobs.open_bytes(blob_id)  # Blob-Store nur im Loop-Thread
        except (KeyError, OSError):
            raise ApiError("not_found") from None
        api.same(p)
        if api.daemon.presentation:  # nicht während des Lesens eingeschaltet
            raise ApiError("policy")
        mime = sniff_image(data)
        if mime not in ALLOWED_MIME:
            raise ApiError("not_found")
        if mime == "image/png":
            try:
                check_png(data)
            except ValueError:
                raise ApiError("not_found") from None
        return Response(
            content=data,
            media_type=mime,
            headers={
                "Content-Disposition": f'inline; filename="screenshot.{ALLOWED_MIME[mime]}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
