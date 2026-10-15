"""Gemeinsame Bausteine der ctl-Operationen (``daemon/core.py`` und ``daemon/ops_eval.py``).

Stabile Schnittstelle laut Vertrag v0.1-Bedienung: Änderungen nur additiv.
"""

from __future__ import annotations

from typing import Any

__all__ = ["OpError", "arg_str", "arg_int"]


class OpError(Exception):
    """Fehler einer ctl-Operation mit maschinenlesbarem ``code``."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def arg_str(args: dict[str, Any], key: str, *, required: bool = True, max_len: int = 4096) -> str | None:
    v = args.get(key)
    if v is None:
        if required:
            raise OpError("invalid", f"Argument fehlt: {key}")
        return None
    if not isinstance(v, str) or len(v) > max_len:
        raise OpError("invalid", f"Argument ungültig: {key}")
    return v


def arg_int(args: dict[str, Any], key: str, lo: int, hi: int, default: int) -> int:
    v = args.get(key)
    if v is None:
        return default
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise OpError("invalid", f"Argument ungültig: {key}")
    return v
