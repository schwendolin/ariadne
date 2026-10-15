"""Export und Bericht (ab v0.2, noch leer).

Pflicht für jeden Ausgang (E72, Vertrag v0.1-Bedienung 4.8): Das Journal speichert eigene
Secrets ungeschwärzt (nur verschlüsselt). Alles, was exportiert oder in einen Bericht
geschrieben wird, läuft vorher durch ``Daemon.redactor.redact_for_exit`` (Text und Bytes)
bzw. ``redact_json`` (Strukturen); längenerhaltend, nur exakte Treffer der eigenen Liste.
"""
