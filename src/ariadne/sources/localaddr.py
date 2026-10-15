"""Eigene Adressen von Kali aus ``/proc`` (Vertrag v0.1-Bedienung 4.9, A5).

Reines Python, kein Befehl, kein Paket, kein Netzverkehr: ``/proc/net/fib_trie``
(Einträge ``/32 host LOCAL``) und ``/proc/net/if_inet6`` (Hex-Adressen). Das Ergebnis
ist die vollständige Menge, kanonisch (``ipaddress``), sortiert, ohne Duplikate und
höchstens :data:`MAX_ADDRS` Einträge; fehlen beide Dateien, ``None``.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

__all__ = ["MAX_ADDRS", "parse_fib_trie", "parse_if_inet6", "canonical", "read_local_addrs"]

MAX_ADDRS = 256
MAX_FILE = 4 << 20
FIB_TRIE = Path("/proc/net/fib_trie")
IF_INET6 = Path("/proc/net/if_inet6")


def parse_fib_trie(text: str) -> set[str]:
    """IPv4-Adressen der Einträge ``/32 host LOCAL``."""
    out: set[str] = set()
    last: str | None = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("|--"):
            last = s[3:].strip()
            continue
        if last is not None and s.startswith("/32") and "host" in s.split() and s.endswith("LOCAL"):
            try:
                out.add(str(ipaddress.IPv4Address(last)))
            except ValueError:
                pass
    return out


def parse_if_inet6(text: str) -> set[str]:
    """IPv6-Adressen aus ``/proc/net/if_inet6`` (erste Spalte, 32 Hex-Zeichen)."""
    out: set[str] = set()
    for line in text.splitlines():
        parts = line.split()
        if not parts or len(parts[0]) != 32:
            continue
        try:
            out.add(str(ipaddress.IPv6Address(int(parts[0], 16))))
        except ValueError:
            pass
    return out


def canonical(addrs: set[str]) -> tuple[str, ...]:
    ips = sorted({ipaddress.ip_address(a) for a in addrs}, key=lambda ip: (ip.version, int(ip)))
    return tuple(str(ip) for ip in ips[:MAX_ADDRS])


def _read(path: Path) -> str | None:
    try:
        with open(path, "rb") as fh:
            return fh.read(MAX_FILE).decode("ascii", "replace")
    except OSError:
        return None


def read_local_addrs(fib_trie: Path = FIB_TRIE, if_inet6: Path = IF_INET6) -> tuple[str, ...] | None:
    """Aktuelle eigene Adressen; ``None``, wenn keine der beiden Dateien lesbar ist."""
    v4 = _read(fib_trie)
    v6 = _read(if_inet6)
    if v4 is None and v6 is None:
        return None
    addrs = (parse_fib_trie(v4) if v4 else set()) | (parse_if_inet6(v6) if v6 else set())
    return canonical(addrs)
