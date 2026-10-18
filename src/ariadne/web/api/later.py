"""Routen, die in diesem Bau mit 501 antworten (``docs/web-api.md`` 15).

Sie existieren, damit die Oberfläche Platz lassen kann; die Middleware und die Anmeldung des
Servers gelten für sie wie für jede andere Route. Danach antworten sie immer
``501 {"error": {"code": "not_implemented", "message": "Kommt in einer späteren Version."}}``.
"""

from __future__ import annotations

from fastapi import APIRouter
from starlette.responses import Response

from ariadne.web.api.errors import ApiError

__all__ = ["add_routes", "LATER_ROUTES"]

# (Methode, Pfad, Name, Version)
LATER_ROUTES: tuple[tuple[str, str, str, str], ...] = (
    ("POST", "/p/{pid}/ai/denkanstoss", "ai_denkanstoss", "v0.1-KI"),
    ("POST", "/p/{pid}/ai/frage", "ai_frage", "v0.2"),
    ("POST", "/p/{pid}/exports", "exports_create", "v0.1-Export"),
    ("GET", "/p/{pid}/exports", "exports_list", "v0.1-Export"),
    ("POST", "/p/{pid}/screenshots", "screenshots", "v0.1-Screenshots"),
    ("GET", "/p/{pid}/credentials", "credentials", "v0.2"),
    ("GET", "/p/{pid}/cred-matrix", "cred_matrix", "v0.2"),
    ("POST", "/p/{pid}/credentials/{cred_id}/copy", "credential_copy", "v0.2"),
    ("POST", "/p/{pid}/query", "query", "v0.2"),
    ("GET", "/p/{pid}/blobs/{blob_id}", "blob", "v0.2"),
)


async def not_implemented() -> Response:
    raise ApiError("not_implemented")


def add_routes(router: APIRouter) -> None:
    for method, path, name, _version in LATER_ROUTES:
        router.add_api_route(path, not_implemented, methods=[method], name=name)
