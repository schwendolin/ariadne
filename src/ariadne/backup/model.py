"""Fehler und Ergebnistypen der Sicherung (Vertrag v0.1-Server 3.5).

Eigenes Modul, damit die Bausteine (``config``, ``manifest``, ``writer``, ``reader``) sie ohne
Kreis-Import nutzen; :mod:`ariadne.backup.api` exportiert sie unverändert weiter.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["BackupError", "BackupResult", "RestoreResult", "CODES"]

# Feste Fehlercodes. Meldungen sind deutsch, ohne Secrets, ohne Zieldaten (keine Dateinamen aus
# Arbeitsbereichen, keine Inhalte), höchstens Slugs, Zeilennummern und Zahlen.
CODES = (
    "not_built", "no_recipients", "bad_recipient", "no_vault", "not_found", "tty_refused",
    "project_open", "vault_exists", "project_exists", "bad_manifest", "version", "hash_mismatch",
    "unsafe_path", "decrypt", "verify_failed", "io",
)


class BackupError(RuntimeError):
    """Fehler mit festem ``code`` und deutscher Meldung ohne Secrets und ohne Zieldaten.

    Codes (Vertrag 3.5, ergänzt im Bau): ``no_recipients`` (keine Empfänger), ``bad_recipient``
    (Empfänger ungültig oder Datei für andere beschreibbar), ``no_vault`` (kein Operator-Tresor),
    ``not_found`` (``--project`` unbekannt), ``tty_refused`` (Terminal als Ausgabe bzw. Eingabe),
    ``project_open``, ``vault_exists``, ``project_exists``, ``bad_manifest`` (Manifest oder Strom
    kaputt, unvollständig, unerwartete Datei), ``version`` (neuere Ariadne oder neueres Format),
    ``hash_mismatch``, ``unsafe_path`` (``..``, absolute Pfade, Links, Geräte), ``decrypt``
    (Entschlüsseln mit ``--identity`` gescheitert), ``verify_failed``, ``io``.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BackupResult:
    bytes_written: int
    projects: tuple[str, ...]  # Slugs
    chain_heads: dict[str, str] = field(default_factory=dict)  # Slug -> Kettenkopf (Hex)
    manifest_sha256: str = ""
    registry_id: str | None = None  # Eintrag in der Registry (Paths.registry_file)
    # ergänzt im Bau (additiv)
    head_seqs: dict[str, int] = field(default_factory=dict)  # Slug -> seq des Kettenkopfs
    files: int = 0  # Dateien im Strom
    plain_bytes: int = 0  # Summe der Dateigrössen vor der Verschlüsselung
    skipped: int = 0  # übersprungene Einträge (Links, Sockets, Geräte), ohne Namen
    recipients: int = 0  # Zahl der age-Empfänger
    unreadable: int = 0  # Arbeitsbereich: fremde oder nicht lesbare Dateien und Ordner (F1)
    grown: int = 0  # Arbeitsbereich: während der Sicherung gewachsen, Anfang gesichert (RT-2)


@dataclass(frozen=True)
class RestoreResult:
    projects: tuple[str, ...]
    operator_restored: bool
    verified: dict[str, bool] = field(default_factory=dict)  # Slug -> Kette in Ordnung
    # ergänzt im Bau (additiv)
    chain_heads: dict[str, str] = field(default_factory=dict)  # Slug -> Kettenkopf laut Manifest
    head_seqs: dict[str, int] = field(default_factory=dict)
    config_added: tuple[str, ...] = ()  # relative Pfade unter ~/.config/ariadne
    config_kept: tuple[str, ...] = ()  # schon vorhanden, nicht überschrieben
    files: int = 0
    manifest_sha256: str = ""
    backup_id: str = ""
    created_utc: str = ""
    ariadne_version: str = ""
