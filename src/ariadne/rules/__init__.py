"""Regel-Engine für Denkanstösse (Architektur 6.1, E64, E68; web-api.md 18.6).

Besitzer: Teil «regeln» des Baus v0.1-Oberfläche. Öffentlich ist nur :mod:`ariadne.rules.api`;
die Web-API (``web/api/next.py``, ``web/api/suggestions.py``, ``web/api/decisions.py``) nutzt nichts
anderes. Die Engine liest nur die Projektion in ``derived.db`` (nie das Journal, nie Rohdaten),
erzeugt nur Vorschläge und führt nie etwas aus (E10).
"""
