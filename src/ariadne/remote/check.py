"""``ariadne remote check``: Systemprüfung für den Fernzugriff (R10, Konzept 7, T14).

Besitzer: Teil «remote». **Stub aus Phase 1**: ``run_checks`` meldet nur, dass die Prüfung
fehlt; ``quick_ok`` ist ``False`` (fail-closed: ``remote serve code`` gibt so keinen Code aus).

Endzustand: Prüfungen wie ``ariadne doctor`` (:class:`ariadne.cli.doctor.Check` mit ``ok``,
``warn``, ``fail``): Bindung von 7330 nur Loopback (``ss -tlnH`` bzw. ``/proc/net/tcp``),
``sshd -T -C user=…,host=…,addr=…`` (ListenAddress, PasswordAuthentication,
AllowTcpForwarding, PermitOpen, …), Hostkey-Marker des Einrichtungsskripts,
``authorized_keys``-Zeile mit ``restrict`` und ``permitopen``, OpenSSH-Version (unter 9.8
Warnung, kein Abbruch), Tailscale-Zustand falls vorhanden, Swap, open-vm-tools, Python.
Alle Programme laufen über einen austauschbaren ``runner`` (Tests mit Fixtures, nie root).
"""

from __future__ import annotations

from ariadne.cli.doctor import FAIL, Check
from ariadne.paths import Paths

__all__ = ["run_checks", "quick_ok"]

# Phase 1: Stub. Der Besitzer setzt STUB = False, sobald die echte Umsetzung steht; abhängige
# Tests anderer Teile überspringen sich bis dahin mit diesem Grund (Vertrag v0.1-Server 4).
STUB = True


def run_checks(paths: Paths, *, full: bool = False) -> list[Check]:
    return [Check(FAIL, "remote check ist noch nicht gebaut")]


def quick_ok(paths: Paths) -> bool:
    """Schnellprüfung vor ``remote serve code`` (ohne root): ``False`` bei einem ``fail``."""
    return False
