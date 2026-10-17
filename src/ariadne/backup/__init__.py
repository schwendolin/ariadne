"""Sicherung und Wiederherstellung (E91, Konzept Fernzugriff 6, Vertrag v0.1-Server).

Besitzer: Teil «backup». Einstiegspunkte für andere Teile (festgelegt in Phase 1):

* :mod:`ariadne.backup.api`: ``backup_to_stream`` und ``restore_from_stream`` (für
  ``ariadne backup``/``restore`` und ``ariadne remote serve backup``/``restore``).
* :mod:`ariadne.backup.reminder`: ``after_stop_lines`` (Hinweis nach ``ariadne stop``).
"""
