"""Bericht-Export als Markdown (Bau v0.1-Export, E62, Architektur 8.7).

Pflicht für jeden Ausgang (E72, Vertrag v0.1-Bedienung 4.8): Das Journal speichert eigene
Secrets ungeschwärzt (nur verschlüsselt). Alles, was exportiert oder in einen Bericht
geschrieben wird, läuft vorher durch ``Daemon.redactor.redact_for_exit`` (Text und Bytes)
bzw. ``redact_json`` (Strukturen); längenerhaltend, nur exakte Treffer der eigenen Liste.

Module:

* :mod:`.collect` sammelt im Thread der Auswertung (eigene Secrets ersetzt, Ziel-Credentials
  maskiert, ausser Klartext im Profil lab mit Bestätigung im Terminal).
* :mod:`.mdsafe` ist der einzige Encoder für Markdown (E13).
* :mod:`.render` baut die Dateien der Vorlagen ``cys`` und ``htb``.
* :mod:`.writer` schreibt per ``openat`` mit ``O_NOFOLLOW | O_EXCL`` nach
  ``<projekt>/exports/<UTC>-<vorlage>/`` und legt ``_ariadne/manifest.json`` an.
* :mod:`.service` steuert den Ablauf (ein Export pro Daemon, Fortschritt), :mod:`.ops` die
  ctl-Operationen für die CLI. Phasen der Befehle: :mod:`ariadne.ingest.proj_phases`.
"""
