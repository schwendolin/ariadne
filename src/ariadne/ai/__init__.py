"""KI-Gateway (ab v0.2, noch leer).

Pflicht für jeden Aufruf (E72, Vertrag v0.1-Bedienung 4.8): Das Journal speichert eigene
Secrets ungeschwärzt (nur verschlüsselt). Alles, was an ein Modell geht, läuft vorher durch
``Daemon.redactor.redact_for_exit`` (Text und Bytes) bzw. ``redact_json`` (Strukturen),
danach durch ``scan_outgoing`` für generische Warnungen.
"""
