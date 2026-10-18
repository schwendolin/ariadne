"""KI-Gateway (Bau v0.1-KI): Denkanstoss auf Knopfdruck (Architektur 6, E64 bis E66).

Module: :mod:`.config` (``ai.toml``, Anbieter, Modell-ID, Limit, Preise), :mod:`.budget` (Monatsbudget),
:mod:`.providers` (``cloud`` über das Anthropic-SDK, ``local`` über Ollama auf 127.0.0.1),
:mod:`.situation` (Lagebild aus der Projektion), :mod:`.schema` (Prompt, Schema, Prüfung),
:mod:`.store` (KI-Denkanstösse lesen, Entscheide prüfen), :mod:`.gateway` (Policy, Auftrag),
:mod:`.ops` (ctl-Operationen der CLI), :mod:`.check` (``ariadne ai check``).

Pflicht für jeden Aufruf (E72, Vertrag v0.1-Bedienung 4.8): Das Journal speichert eigene
Secrets ungeschwärzt (nur verschlüsselt). Alles, was an ein Modell geht, läuft vorher durch
``Daemon.redactor.redact_for_exit`` (Text und Bytes) bzw. ``redact_json`` (Strukturen),
danach durch ``scan_outgoing`` für generische Warnungen.
"""
