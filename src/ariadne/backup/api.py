"""Öffentliche Schnittstelle der Sicherung (Vertrag v0.1-Server, Abschnitt 3.5).

Besitzer: Teil «backup». **Stub aus Phase 1**: Signaturen und Ergebnistypen sind festgelegt,
die Funktionen werfen :class:`BackupError` mit Code ``not_built``.

Format (Endzustand, Details legt der Teil «backup» fest und dokumentiert sie hier):

* Aussen age (``pyrage``) an alle Empfänger aus der Konfiguration (``[backup] recipients`` in
  ``config.toml`` und ``~/.config/ariadne/backup-recipients.txt``, nur X25519 ``age1…``).
  Ohne Empfänger: Fehler ``no_recipients``, nie unverschlüsselt.
* Innen ein Strom aus Manifest (Format-Version, Ariadne-Version, Zeit, Kettenköpfe pro
  Projekt, SHA-256 jeder Datei) und den Dateien: Operator-Tresor immer, je Projekt
  ``.vault/`` ohne ``derived*.db`` (wird nach dem Zurückspielen neu gebaut) und der
  Arbeitsbereich, dazu ``~/.config/ariadne``. Keine Runtime-Ordner, keine Logs.
* Ein offenes Projekt wird nicht gesichert: Die Sicherung nimmt pro Projekt den ``flock`` auf
  ``.vault/.lock`` (wie der Daemon) und bricht ab, wenn er gehalten wird (Code
  ``project_open``: zuerst ``ariadne stop`` oder ``ariadne lock``).

``restore_from_stream`` liest den **inneren Klartext-Strom** (entschlüsselt auf dem Mac oder
mit ``--identity`` in der VM), prüft Manifest und Version, schreibt nur in eine Installation
ohne Operator-Tresor bzw. ohne gleichnamiges Projekt, legt Ordner mit 0700 an und prüft
danach jede Kette (wie ``ariadne verify``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import BinaryIO

from ariadne.paths import Paths

__all__ = ["BackupError", "BackupResult", "RestoreResult", "backup_to_stream", "restore_from_stream"]

# Phase 1: Stub. Der Besitzer setzt STUB = False, sobald die echte Umsetzung steht; abhängige
# Tests anderer Teile überspringen sich bis dahin mit diesem Grund (Vertrag v0.1-Server 4).
STUB = True


class BackupError(RuntimeError):
    """Fehler mit festem ``code`` und deutscher Meldung ohne Secrets und ohne Zieldaten.

    Codes (Vertrag 3.5): ``not_built``, ``no_recipients``, ``tty_refused``, ``project_open``,
    ``vault_exists``, ``project_exists``, ``bad_manifest``, ``version``, ``hash_mismatch``,
    ``verify_failed``, ``io``.
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


@dataclass(frozen=True)
class RestoreResult:
    projects: tuple[str, ...]
    operator_restored: bool
    verified: dict[str, bool] = field(default_factory=dict)  # Slug -> Kette in Ordnung


def backup_to_stream(out: BinaryIO, paths: Paths, *, projects: list[str] | None = None) -> BackupResult:
    """Schreibt die age-verschlüsselte Sicherung nach ``out`` (Datei oder Pipe, nie ein Terminal).

    ``projects`` ``None``: alle Projekte. Der Operator-Tresor ist immer dabei (E91).
    """
    raise BackupError("not_built", "Sicherung ist noch nicht gebaut")


def restore_from_stream(inp: BinaryIO, paths: Paths) -> RestoreResult:
    """Stellt eine Sicherung aus dem entschlüsselten Strom ``inp`` wieder her (nur ohne Tresor)."""
    raise BackupError("not_built", "Wiederherstellung ist noch nicht gebaut")
