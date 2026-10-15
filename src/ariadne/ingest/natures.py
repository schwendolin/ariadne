"""Arten von Prädikaten (E45 präzisiert, Vertrag 6.4): Verlauf statt Widerspruch.

* ``fact``: zwei Werte sind ein Widerspruch.
* ``state``: der neueste Wert (Shim-Zeit) gilt, ältere sind Verlauf. Gleich neue
  verschiedene Werte bleiben ein Widerspruch.
* ``version``: ein spezifischerer Wert im Bereich des allgemeineren ersetzt ihn
  (:func:`refines`), der allgemeinere ist Verlauf; sonst Widerspruch.
* ``set``: nie ein Widerspruch (Kardinalität ``many``).

Reine Funktionen ohne Regex über Zieldaten (nur String-Operationen).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TypeVar

__all__ = ["refines", "split_heads"]

T = TypeVar("T")

_BOUNDARY = frozenset(" ./-_:(+~,;[")
_WILD = frozenset({"x", "X", "*"})
_INF = 1 << 62
_MAX_LEN = 256


def _components(token: str) -> list[str] | None:
    """Versionsbestandteile (``3.0.20`` -> ``['3', '0', '20']``), ``X`` als Platzhalter erlaubt."""
    parts = token.split(".")
    if not parts or len(parts) > 8:
        return None
    for p in parts:
        if not p or (not p.isdigit() and p not in _WILD) or len(p) > 9:
            return None
    return parts


def _leading_version(text: str) -> list[int] | None:
    """Ziffern und Punkte am Anfang (``3.0.20-Debian`` -> ``[3, 0, 20]``)."""
    end = 0
    while end < len(text) and (text[end].isdigit() or text[end] == "."):
        end += 1
    token = text[:end].rstrip(".")
    comps = _components(token) if token else None
    if comps is None or any(not c.isdigit() for c in comps):
        return None
    if end < len(text) and text[end] not in _BOUNDARY:
        return None  # 2.6abc ist keine Version 2.6
    return [int(c) for c in comps]


def _bound(comps: list[str], *, upper: bool) -> list[int]:
    return [(_INF if upper else 0) if c in _WILD else int(c) for c in comps]


def _in_range(lo: list[str], hi: list[str], value: list[int]) -> bool:
    low, high = _bound(lo, upper=False), _bound(hi, upper=True)
    return value[: len(low)] >= low and value[: len(high)] <= high


def _range(text: str) -> tuple[list[str], list[str]] | None:
    """``3.X - 4.X`` oder ``8.3.0 - 8.3.7``."""
    a, sep, b = text.partition(" - ")
    if not sep:
        return None
    lo, hi = _components(a.strip()), _components(b.strip())
    if lo is None or hi is None:
        return None
    return lo, hi


def refines(general: str, specific: str) -> bool:
    """Ist ``specific`` spezifischer als ``general`` und liegt im Bereich von ``general``?

    Fälle: Bereich mit oder ohne X («3.X - 4.X» -> «3.0.20-Debian»), Muster mit X
    («2.6.X» -> «2.6.24») und Präfix an einer Wortgrenze («Apache httpd» ->
    «Apache httpd 2.2.8», «distccd» -> «distccd v1»). Verschiedene Produkte
    («vsftpd» gegen «ProFTPD») und verschiedene Versionen («2.3.4» gegen «2.3.5»)
    verfeinern sich nie.
    """
    g, s = general.strip(), specific.strip()
    if not g or not s or g == s or len(g) > _MAX_LEN or len(s) > _MAX_LEN:
        return False
    rng = _range(g)
    if rng is not None:
        if _range(s) is not None:
            return False  # zwei Bereiche: keiner ist ein einzelner Wert
        value = _leading_version(s)
        return value is not None and _in_range(rng[0], rng[1], value)
    pattern = _components(g)
    if pattern is not None and any(c in _WILD for c in pattern):
        value = _leading_version(s)
        if value is None or len(value) < len(pattern):
            return False
        return all(p in _WILD or int(p) == v for p, v in zip(pattern, value, strict=False))
    if len(s) > len(g) and s.casefold().startswith(g.casefold()):
        rest = s[len(g):]
        informative = any(c not in _BOUNDARY and c not in _WILD for c in rest)  # «2.6» -> «2.6.X» nicht
        return rest[0] in _BOUNDARY and g[-1] not in _BOUNDARY and informative
    return False


def split_heads(items: Sequence[T], nature: str, *, value: Callable[[T], str],
                newest: Callable[[T], tuple[int, ...]]) -> tuple[list[T], list[T]]:
    """Teilt die Werte eines Prädikats in geltende Werte (``heads``) und Verlauf.

    Mehr als ein geltender Wert ist ein Widerspruch. ``fact`` hat nie Verlauf.
    """
    items = list(items)
    if len(items) < 2 or nature not in ("state", "version"):
        return items, []
    if nature == "state":
        top = max(newest(i) for i in items)
        heads = [i for i in items if newest(i) == top]
        return heads, [i for i in items if newest(i) != top]
    history = [i for i in items if any(j is not i and refines(value(i), value(j)) for j in items)]
    heads = [i for i in items if not any(i is h for h in history)]
    return heads, history
