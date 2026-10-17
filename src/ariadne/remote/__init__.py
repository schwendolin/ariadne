"""Fernzugriff über Tailscale und SSH (E89, E90, E93, E94, E100, Konzept Fernzugriff 4.2, 4.4, 7).

Besitzer: Teil «remote». Einstiegspunkte (festgelegt in Phase 1):

* :mod:`ariadne.remote.serve`: ``main`` für den Forced Command ``ariadne remote serve`` (R5, R11).
* :mod:`ariadne.remote.check`: ``run_checks`` und ``quick_ok`` für ``ariadne remote check`` (R10).

Dazu ``packaging/smartlearn/kali-setup.sh``, ``packaging/mac/ariadne-mac`` und
``docs/anleitung-fernzugriff.md``. Ariadne ändert keine Systemdienste; das Einrichtungsskript
läuft bewusst mit ``sudo`` und zeigt jede Änderung vor dem Schreiben.
"""
