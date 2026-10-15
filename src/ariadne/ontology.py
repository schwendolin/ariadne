"""Ontologie v2: Prädikate, Kardinalität, Art, Kartenebene, Wichtigkeit (Architektur 5.7, E45).

Die Ontologie ist versioniert. Eine Änderung an Kardinalität, Art oder Ebene
erhöht :data:`VERSION` und löst ein Reparse-Angebot aus.

* ``nature`` (Art, E45 präzisiert): ``fact`` (zwei Werte sind ein Widerspruch),
  ``state`` (der neueste Wert gilt, ältere sind Verlauf), ``version`` (ein
  spezifischerer Wert im Bereich des allgemeineren ersetzt ihn, etwa «3.X - 4.X»
  durch «3.0.20-Debian» oder «distccd» durch «distccd v1»; sonst Widerspruch),
  ``set`` (mehrere Werte, nie ein Widerspruch). ``set`` gehört immer zu ``many``.
* ``important``: heuristische Werte gehen hier zum Entscheiden statt still zu
  bleiben (Drei-Spuren-Regel, E42: Login-Ergebnis, Admin-Bereich, Secret).
* ``inbox`` gilt nur noch für das Profil customer (Vorschlag in die Inbox wie
  bisher); im Profil lab entscheidet die Drei-Spuren-Regel.

v2 (2026-10-15): ``nature`` und ``important`` neu. Die geplante Erweiterung um
Konten, Credential-Tests und Hinweise (Konzept 3.5) wird v3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

__all__ = ["VERSION", "Predicate", "PREDICATES", "predicate", "Nature"]

VERSION = 2

Cardinality = Literal["one", "many"]
Nature = Literal["fact", "state", "version", "set"]
MapLayer = Literal["topology", "services", "creds", "attack", "web", "ad", "none"]
ValueType = Literal["str", "int", "bool", "ref", "ip", "mac", "fqdn", "url", "cpe", "level"]


@dataclass(frozen=True)
class Predicate:
    name: str
    subject: str  # host | service | identity | secret | url | cred_test | hint | edge
    value: ValueType
    cardinality: Cardinality
    layer: MapLayer
    inbox: bool = True  # Profil customer: neue Werte erscheinen in der Inbox
    nature: Nature = "fact"
    important: bool = False  # heuristische Werte gehen zum Entscheiden (E42)

    def __post_init__(self) -> None:
        if (self.nature == "set") != (self.cardinality == "many"):
            raise ValueError(f"{self.name}: Art set genau bei Kardinalität many")


_P = Predicate
PREDICATES: dict[str, Predicate] = {
    p.name: p
    for p in [
        # Host
        _P("host.state", "host", "str", "one", "topology", nature="state"),  # up | down
        _P("host.address", "host", "ip", "many", "topology", nature="set"),
        _P("host.mac", "host", "mac", "many", "topology", nature="set"),
        _P("host.name", "host", "fqdn", "many", "topology", nature="set"),
        _P("host.netbios", "host", "str", "many", "topology", nature="set"),
        _P("host.os", "host", "str", "one", "topology", nature="version"),
        _P("host.domain", "host", "str", "one", "ad"),
        # Ergänzungen v1 (nur neue Prädikate, daher keine neue Version)
        # host.sshkey: Wert sshkey:<typ>:<fp>; host.script: NSE-Hostskript, attrs: output
        _P("host.sshkey", "host", "ref", "many", "none", inbox=False, nature="set"),
        _P("host.smb_os", "host", "str", "one", "none", inbox=False, nature="version"),  # smb-os-discovery
        _P("host.smb_domain", "host", "str", "one", "ad", inbox=False),  # NetBIOS-Domäne/Workgroup
        _P("host.script", "host", "str", "many", "none", inbox=False, nature="set"),
        # Service
        _P("service.state", "service", "str", "one", "services", nature="state"),  # open | filtered | closed
        _P("service.name", "service", "str", "one", "services"),
        _P("service.product", "service", "str", "one", "services", nature="version"),
        _P("service.version", "service", "str", "one", "services", nature="version"),
        _P("service.extrainfo", "service", "str", "one", "services", inbox=False),
        _P("service.cpe", "service", "cpe", "many", "services", inbox=False, nature="set"),
        _P("service.tunnel", "service", "str", "one", "services", inbox=False),  # ssl
        _P("service.ssh_hostkey", "service", "str", "many", "services", inbox=False, nature="set"),
        _P("service.tls_cn", "service", "str", "many", "services", inbox=False, nature="set"),
        _P("service.script", "service", "str", "many", "none", inbox=False, nature="set"),
        # Web
        _P("url.status", "url", "int", "one", "web", nature="state"),
        _P("url.title", "url", "str", "one", "web", inbox=False, nature="state"),
        # Identitäten und Secrets
        _P("identity.exists", "identity", "bool", "one", "creds"),
        _P("identity.secret", "identity", "ref", "many", "creds", nature="set", important=True),
        _P("secret.kind", "secret", "str", "one", "creds", important=True),
        # Zugriff (Kanten für Faden und Status)
        _P("access.shell", "host", "level", "many", "attack", nature="set", important=True),  # user | admin
        _P("access.callback", "host", "str", "many", "attack", nature="set"),  # Listener-Callback
        # Hinweise
        _P("hint.cve", "service", "str", "many", "services", nature="set"),
        _P("hint.finding", "host", "str", "many", "services", nature="set"),
    ]
}


def predicate(name: str) -> Predicate:
    try:
        return PREDICATES[name]
    except KeyError as exc:
        raise KeyError(f"unbekanntes Prädikat {name!r} (Ontologie v{VERSION})") from exc
