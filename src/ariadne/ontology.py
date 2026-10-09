"""Ontologie v1: Prädikate, Kardinalität, Kartenebene, Inbox-Regel (Architektur 5.7).

Die Ontologie ist versioniert. Eine Änderung an Kardinalität oder Ebene
erhöht :data:`VERSION` und löst ein Reparse-Angebot aus.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = ["VERSION", "Predicate", "PREDICATES", "predicate"]

VERSION = 1

Cardinality = Literal["one", "many"]
MapLayer = Literal["topology", "services", "creds", "attack", "web", "ad", "none"]
ValueType = Literal["str", "int", "bool", "ref", "ip", "mac", "fqdn", "url", "cpe", "level"]


@dataclass(frozen=True)
class Predicate:
    name: str
    subject: str  # host | service | identity | secret | url | cred_test | hint | edge
    value: ValueType
    cardinality: Cardinality
    layer: MapLayer
    inbox: bool = True  # neue Werte erscheinen in der Inbox


_P = Predicate
PREDICATES: dict[str, Predicate] = {
    p.name: p
    for p in [
        # Host
        _P("host.state", "host", "str", "one", "topology"),  # up | down
        _P("host.address", "host", "ip", "many", "topology"),
        _P("host.mac", "host", "mac", "many", "topology"),
        _P("host.name", "host", "fqdn", "many", "topology"),
        _P("host.netbios", "host", "str", "many", "topology"),
        _P("host.os", "host", "str", "one", "topology"),
        _P("host.domain", "host", "str", "one", "ad"),
        # Service
        _P("service.state", "service", "str", "one", "services"),  # open | filtered | closed
        _P("service.name", "service", "str", "one", "services"),
        _P("service.product", "service", "str", "one", "services"),
        _P("service.version", "service", "str", "one", "services"),
        _P("service.extrainfo", "service", "str", "one", "services", inbox=False),
        _P("service.cpe", "service", "cpe", "many", "services", inbox=False),
        _P("service.tunnel", "service", "str", "one", "services", inbox=False),  # ssl
        _P("service.ssh_hostkey", "service", "str", "many", "services", inbox=False),
        _P("service.tls_cn", "service", "str", "many", "services", inbox=False),
        _P("service.script", "service", "str", "many", "none", inbox=False),
        # Web
        _P("url.status", "url", "int", "one", "web"),
        _P("url.title", "url", "str", "one", "web", inbox=False),
        # Identitäten und Secrets
        _P("identity.exists", "identity", "bool", "one", "creds"),
        _P("identity.secret", "identity", "ref", "many", "creds"),
        _P("secret.kind", "secret", "str", "one", "creds"),
        # Zugriff (Kanten für Faden und Status)
        _P("access.shell", "host", "level", "many", "attack"),  # user | admin, attrs: via
        _P("access.callback", "host", "str", "many", "attack"),  # Listener-Callback
        # Hinweise
        _P("hint.cve", "service", "str", "many", "services"),
        _P("hint.finding", "host", "str", "many", "services"),
    ]
}


def predicate(name: str) -> Predicate:
    try:
        return PREDICATES[name]
    except KeyError as exc:
        raise KeyError(f"unbekanntes Prädikat {name!r} (Ontologie v{VERSION})") from exc
