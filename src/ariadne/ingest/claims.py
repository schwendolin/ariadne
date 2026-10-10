"""Claims: Werte normalisieren, Schlüssel bilden, Konfidenz kombinieren (Architektur 5.7).

* ``claim_key = sha256(kanon([kennung, prädikat, normalisierter_wert]))``. Ist
  Subjekt oder Wert ein Secret, gilt ``secret_key(projektschlüssel, "claim", ...)``.
* Konfidenz: Basis je Vertrauensklasse, ein Parser darf nur senken; pro Einheit
  das Maximum, über Einheiten noisy-OR, höchstens 0.99. Nutzerwerte haben 1.0.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from ariadne.events import canonical_json
from ariadne.ingest.identity import (
    canon_hostname,
    canon_ip,
    canon_mac,
    id_type,
    normalize_identifier,
)
from ariadne.ontology import Predicate
from ariadne.parsers.api import BASE_CONFIDENCE
from ariadne.store.chain import secret_key

__all__ = [
    "MAX_CONFIDENCE",
    "TRUST_ORDER",
    "normalize_value",
    "value_identifier",
    "claim_key",
    "conflict_key",
    "effective_confidence",
    "combine",
    "confidence_level",
    "STATE_RANK",
]

MAX_CONFIDENCE = 0.99
MAX_STR = 4096
TRUST_ORDER = {"user": 0, "structured": 1, "tool_text": 2, "ai": 3, "ocr": 4, "heuristic": 5}
STATE_RANK = {"confirmed": 0, "auto": 1, "candidate": 2, "rejected": 3}
_LEVELS = {"user": "user", "admin": "admin", "root": "admin", "system": "admin"}


class _Bad(ValueError):
    pass


def normalize_value(pred: Predicate, value: Any, project_key: bytes,
                    secret_sink: Callable[[str, str, str], None] | None = None
                    ) -> tuple[Any, str, bool]:
    """Normalisierter Wert (JSON-fähig), Anzeigetext und ob er ein Secret ist.

    Wirft ``ValueError`` bei ungültigen Werten.
    """
    ref = None
    if isinstance(value, Mapping) and set(value) == {"ref"} and isinstance(value["ref"], str):
        ref = value["ref"]
    elif hasattr(value, "key") and isinstance(getattr(value, "key", None), str):
        ref = value.key
    if isinstance(value, bool) and pred.value != "bool":
        raise _Bad("bool")
    vt = pred.value
    if ref is not None:
        ident = normalize_identifier(ref, project_key, secret_sink=secret_sink)
        if ident is None:
            raise _Bad("ref")
        if vt == "ref":
            secret = id_type(ident) == "secret"
            return {"ref": ident}, ident, secret
        if vt == "ip" and id_type(ident) == "ip":
            return ident.split("/", 1)[1], ident.split("/", 1)[1], False
        raise _Bad("ref für Nicht-ref-Prädikat")
    if vt == "ref":
        raise _Bad("ref erwartet")
    if vt == "bool":
        if not isinstance(value, bool):
            raise _Bad("bool erwartet")
        return value, "true" if value else "false", False
    if vt == "int":
        if not isinstance(value, int):
            raise _Bad("int erwartet")
        return value, str(value), False
    if not isinstance(value, str):
        raise _Bad("str erwartet")
    s = value.strip()
    if not s or len(s) > MAX_STR:
        raise _Bad("leer oder zu lang")
    if vt == "ip":
        ip = canon_ip(s)
        if ip is None:
            raise _Bad("ip")
        return ip, ip, False
    if vt == "mac":
        mac = canon_mac(s)
        if mac is None:
            raise _Bad("mac")
        return mac, mac, False
    if vt == "fqdn":
        name = canon_hostname(s)
        if name is None:
            raise _Bad("fqdn")
        return name, name, False
    if vt == "cpe":
        c = s.lower()
        if not c.startswith("cpe:"):
            raise _Bad("cpe")
        return c, c, False
    if vt == "level":
        lv = _LEVELS.get(s.lower())
        if lv is None:
            raise _Bad("level")
        return lv, lv, False
    return s, s, False


def value_identifier(pred_name: str, subject: str, value: Any) -> str | None:
    """Kennung, die ein Wert für Identitäten ergibt (``host.address`` -> ``ip:..``)."""
    if pred_name == "host.address" and isinstance(value, str):
        space = "default"
        if id_type(subject) == "ip":
            space = subject[3:].split("/", 1)[0]
        return f"ip:{space}/{value}"
    if pred_name == "host.mac" and isinstance(value, str):
        return f"mac:{value}"
    if pred_name == "host.name" and isinstance(value, str):
        return f"fqdn:{value}"
    if pred_name == "host.netbios" and isinstance(value, str):
        return normalize_identifier(f"netbios:{value}")
    if pred_name == "host.sshkey" and isinstance(value, Mapping):
        return value.get("ref")
    return None


def claim_key(subject: str, predicate: str, value: Any, *, secret: bool, project_key: bytes) -> str:
    data = canonical_json([subject, predicate, value])
    if secret or id_type(subject) == "secret":
        return secret_key(project_key, "claim", data)
    return hashlib.sha256(data).hexdigest()


def conflict_key(subject: str, predicate: str) -> str:
    return hashlib.sha256(canonical_json(["conflict", subject, predicate])).hexdigest()


def effective_confidence(trust: str, parser_conf: float | None) -> float:
    base = BASE_CONFIDENCE[trust]  # type: ignore[index]
    if parser_conf is None:
        return base
    try:
        c = float(parser_conf)
    except (TypeError, ValueError):
        return base
    if c != c or c < 0:  # NaN oder negativ
        return 0.0
    return min(base, c)


def combine(per_unit: Iterable[float]) -> float:
    """noisy-OR über Einheiten, höchstens 0.99."""
    rest = 1.0
    for c in per_unit:
        rest *= 1.0 - max(0.0, min(1.0, c))
    return round(min(MAX_CONFIDENCE, 1.0 - rest), 6)


def confidence_level(c: float) -> str:
    if c >= 0.8:
        return "high"
    if c >= 0.5:
        return "medium"
    return "low"
