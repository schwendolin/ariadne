"""Scope-Schnittstelle (Architektur 5.8).

``ScopeMatcher.check`` ist die einzige Scope-Funktion im System. Scope gehört
zur konkreten Kennung, nie zur Entität. ``unknown`` ist nie ``in``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

__all__ = ["VerdictKind", "Verdict", "ScopeChecker"]

VerdictKind = Literal["in", "out", "excluded", "outside_window", "unknown"]


@dataclass(frozen=True)
class Verdict:
    verdict: VerdictKind
    rule: str | None  # welche Regel gegriffen hat, z. B. "include:10.10.10.0/24"
    scope_version: int

    @property
    def is_in(self) -> bool:
        return self.verdict == "in"


@runtime_checkable
class ScopeChecker(Protocol):
    version: int

    def check(self, identifier: str, at_utc_ns: int | None = None) -> Verdict:
        """Urteil für eine Kennung (``ip:default/10.0.0.1``, ``fqdn:web.lab``,
        ``url:http://...``, ``svc:ip:default/10.0.0.1|tcp/80``) oder einen
        rohen Wert (IP, Name, URL), der vorher normalisiert wird."""
        ...
