"""Sicherung und Wiederherstellung (E91, Konzept Fernzugriff 6, Vertrag v0.1-Server 3.5).

Besitzer: Teil «backup». Einstiegspunkte für andere Teile:

* :mod:`ariadne.backup.api`: ``backup_to_stream`` und ``restore_from_stream`` (für
  ``ariadne backup``/``restore`` und ``ariadne remote serve backup``/``restore``), dazu
  ``backup_summary_lines`` und ``restore_summary_lines`` für Meldungen ohne Zieldaten.
* :mod:`ariadne.backup.reminder`: ``after_stop_lines`` (Hinweis nach ``ariadne stop``).

Bausteine: ``model`` (Fehler, Ergebnisse), ``config`` (Empfänger), ``manifest`` (Format,
Versionen, Pfadregeln), ``collect`` (Auswahl, Sperren, erster Durchgang), ``writer`` (Tar-Strom
und age), ``reader`` (Prüfen, temporäre Ordner, an den Platz bringen), ``registry``.
"""
