"""Öffentliche Schnittstelle der Sicherung (Vertrag v0.1-Server, Abschnitt 3.5, E91).

Nutzer: ``ariadne backup``/``restore`` (:mod:`ariadne.cli.backup`) und ``ariadne remote serve
backup``/``restore`` (:mod:`ariadne.remote.serve`).

Format:

* Aussen age (``pyrage``) an alle Empfänger aus der Konfiguration (``[backup] recipients`` in
  ``config.toml`` und ``~/.config/ariadne/backup-recipients.txt``, nur X25519 ``age1…``, siehe
  :mod:`ariadne.backup.config`). Ohne Empfänger: ``no_recipients``, nie unverschlüsselt.
* Innen ein Tar-Strom (PAX): zuerst das Manifest ``ariadne-backup.json`` (Format
  ``ariadne.backup/1``, Ariadne-Version, Zeit, öffentlicher Operator-Recipient, Projekte mit
  Kettenkopf aus ``.vault/head.json``, Ordner, Dateien mit Grösse, SHA-256 und Modus, siehe
  :mod:`ariadne.backup.manifest`), dann ``operator/``, ``config/`` und ``projects/<slug>/``.
  Im Notfall geht ``age -d -i SCHLÜSSEL DATEI | tar -t`` ohne Ariadne.
* Operator-Tresor immer, je Projekt ``.vault/`` ohne ``derived*`` (wird neu gebaut), ohne
  ``*-shm`` und ``.lock``, aber **mit** ``*-wal`` (nach einem Absturz stehen dort bestätigte
  Einträge der Kette), und der Arbeitsbereich, dazu ``~/.config/ariadne``. Keine Runtime-Ordner,
  keine Logs, keine Sockets, keine Links (:mod:`ariadne.backup.collect`).
* Ein offenes Projekt wird nicht gesichert: ``flock`` auf ``.vault/.lock`` wie der Daemon, sonst
  ``project_open`` (zuerst ``ariadne lock`` oder ``ariadne stop``). Datenbanken öffnet die
  Sicherung nie, Schlüssel braucht sie nicht.
* Jede Datei wird zweimal gelesen (erst hashen fürs Manifest, dann schreiben und erneut prüfen);
  ändert sich etwas, bricht die Sicherung ab, **bevor** age den Strom abschliesst (nie eine
  gültige, aber unvollständige Sicherung).

``restore_from_stream`` liest den **inneren Klartext-Strom** (entschlüsselt auf dem Mac oder
mit ``ariadne restore --identity`` in der VM), prüft Manifest, Version, Pfade, Grössen und
Hashes, schreibt nur in eine Installation ohne Operator-Tresor und ohne gleichnamiges Projekt,
zuerst in temporäre Ordner und erst nach allen Prüfungen an den Platz (Ordner 0700, Dateien
0600), siehe :mod:`ariadne.backup.reader`. Die Ketten prüft danach ``ariadne restore`` über den
Daemon (oder der Nutzer mit ``ariadne unlock``, ``project open``, ``verify``).
"""

from __future__ import annotations

import hashlib
import os
import stat
import time
from typing import Any, BinaryIO

from ariadne import __version__
from ariadne.backup.collect import Selection, select
from ariadne.backup.config import load_recipients
from ariadne.backup.manifest import FORMAT, MANIFEST_NAME, encode_manifest
from ariadne.backup.model import BackupError, BackupResult, RestoreResult
from ariadne.backup.reader import restore_stream
from ariadne.backup.registry import add_entry
from ariadne.backup.writer import encrypt_stream, tar_chunks
from ariadne.ids import new_id
from ariadne.paths import Paths
from ariadne.termsafe import term_safe

__all__ = ["BackupError", "BackupResult", "RestoreResult", "backup_to_stream", "restore_from_stream",
           "backup_summary_lines", "restore_summary_lines", "STUB"]

# Phase 1 hatte hier einen Stub; seit dem Bau v0.1-Server ist die Sicherung echt (Vertrag 4).
STUB = False


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _file_identity(stream: Any) -> set[tuple[int, int]]:
    """``(dev, ino)`` einer Zieldatei, damit eine Sicherung nach ``~/ariadne/x/exports`` sich nicht selbst
    enthält."""
    try:
        st = os.fstat(stream.fileno())
    except (AttributeError, ValueError, OSError):
        return set()
    return {(st.st_dev, st.st_ino)} if stat.S_ISREG(st.st_mode) else set()


def _manifest(sel: Selection, backup_id: str, created: str) -> dict[str, Any]:
    return {
        "format": FORMAT,
        "backup_id": backup_id,
        "created_utc": created,
        "ariadne_version": __version__,
        "operator": {"recipient": sel.operator_recipient},
        "projects": [{"slug": p.slug, "project_id": p.project_id, "profile": p.profile, "head": p.head}
                     for p in sel.projects],
        "dirs": [{"path": e.arc, "mode": e.mode} for e in sel.entries if e.is_dir],
        "files": [{"path": e.arc, "size": e.size, "sha256": e.sha256, "mode": e.mode, "mtime": e.mtime}
                  for e in sel.entries if not e.is_dir],
        "skipped": sel.skipped,
        "unreadable": sel.unreadable,
    }


def backup_to_stream(out: BinaryIO, paths: Paths, *, projects: list[str] | None = None,
                     target: str = "stdout", target_path: str | None = None,
                     register: bool = True) -> BackupResult:
    """Schreibt die age-verschlüsselte Sicherung nach ``out`` (Datei oder Pipe, nie ein Terminal).

    ``projects`` ``None``: alle Projekte. Der Operator-Tresor ist immer dabei (E91). Danach ein
    Eintrag in der Registry (``target`` ``stdout`` oder ``file`` mit ``target_path``); scheitert
    nur dieser Eintrag, ist ``registry_id`` ``None`` und die Sicherung trotzdem gültig.
    Fehler: :class:`BackupError` (``tty_refused``, ``no_recipients``, ``bad_recipient``,
    ``no_vault``, ``not_found``, ``project_open``, ``io``); ``out`` hat dann höchstens einen
    unbrauchbaren Anfang (nie einen gültigen, aber unvollständigen age-Strom).
    """
    if _is_tty(out):
        raise BackupError("tty_refused", "Die Sicherung ist binär und geht nie auf ein Terminal. Umleiten "
                                         "(> datei.age) oder ariadne backup --to-file PFAD.")
    recips = load_recipients(paths)
    sel = select(paths, projects, exclude=_file_identity(out))
    try:
        created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        backup_id = new_id()
        manifest = encode_manifest(_manifest(sel, backup_id, created))
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        written = encrypt_stream(tar_chunks(MANIFEST_NAME, manifest, sel.entries, int(time.time())), out,
                                 recips.recipients)
    finally:
        sel.release()
    slugs = [p.slug for p in sel.projects]
    registry_id: str | None = None
    if register:
        try:
            add_entry(paths, entry_id=backup_id, ts_utc=created, projects=slugs, manifest_sha256=manifest_sha,
                      target="file" if target == "file" else "stdout",
                      path=target_path if target == "file" else None)
            registry_id = backup_id
        except (OSError, ValueError):
            registry_id = None
    files = sel.files
    return BackupResult(
        bytes_written=written, projects=tuple(slugs),
        chain_heads={p.slug: str(p.head["head_hash"]) for p in sel.projects if p.head},
        manifest_sha256=manifest_sha, registry_id=registry_id,
        head_seqs={p.slug: int(p.head["head_seq"]) for p in sel.projects if p.head},
        files=len(files), plain_bytes=sum(e.size for e in files), skipped=sel.skipped,
        recipients=len(recips.recipients), unreadable=sel.unreadable, grown=sel.grown,
    )


def restore_from_stream(inp: BinaryIO, paths: Paths) -> RestoreResult:
    """Stellt eine Sicherung aus dem entschlüsselten Strom ``inp`` wieder her (nur ohne Tresor).

    Prüft vor dem ersten Lesen, ob schon ein Operator-Tresor existiert (``vault_exists``).
    ``verified`` bleibt leer: Die Ketten prüft der Aufrufer über den Daemon (Vertrag 3.5).
    """
    return restore_stream(inp, paths)


# --------------------------------------------------------------------------- #
# Meldungen (für CLI und remote serve, ohne Zieldaten)
# --------------------------------------------------------------------------- #


def _mib(n: int) -> str:
    return f"{n / (1 << 20):.1f} MiB"


def _projects(n: int) -> str:
    return "1 Projekt" if n == 1 else f"{n} Projekte"


def _heads(chain_heads: dict[str, str], seqs: dict[str, int], slugs: tuple[str, ...]) -> list[str]:
    lines = []
    for slug in slugs:
        if slug in chain_heads:
            lines.append(f"  Kettenkopf {slug}: seq {seqs.get(slug, '?')} {chain_heads[slug]}")
        else:
            lines.append(f"  Kettenkopf {slug}: unbekannt (Projekt nie mit dieser Version geschlossen)")
    return lines


def backup_summary_lines(res: BackupResult) -> list[str]:
    """Kurze Zusammenfassung für stderr (stdout trägt bei ``backup`` die Daten)."""
    names = ", ".join(res.projects) if res.projects else "keine"
    lines = [f"Sicherung geschrieben: Operator-Tresor und {_projects(len(res.projects))} ({names}), "
             f"{res.files} Dateien, {_mib(res.plain_bytes)}, verschlüsselt an {res.recipients} Empfänger "
             f"({_mib(res.bytes_written)})."]
    lines += _heads(res.chain_heads, res.head_seqs, res.projects)
    if res.skipped:
        lines.append(f"  Übersprungen: {res.skipped} Links, Sockets oder Geräte (nie mitgesichert).")
    if res.unreadable:
        lines.append(f"  WARNUNG: {res.unreadable} Dateien oder Ordner im Arbeitsbereich nicht gesichert "
                     f"(nicht lesbar oder einem anderen Benutzer). Mitsichern: sudo chown -R \"$USER\" "
                     f"~/ariadne/SLUG, dann neu sichern.")
    if res.grown:
        lines.append(f"  Hinweis: {res.grown} Dateien im Arbeitsbereich wuchsen während der Sicherung "
                     f"(ein Werkzeug schreibt noch); gesichert ist ihr Stand beim ersten Lesen.")
    if res.registry_id is None:
        lines.append("  Hinweis: Eintrag in der Registry gescheitert (die Sicherung selbst ist gültig).")
    return lines


def restore_summary_lines(res: RestoreResult, *, remote: bool = False) -> list[str]:
    """Zusammenfassung nach dem Zurückspielen, mit dem Weg zur Kettenprüfung."""
    names = ", ".join(res.projects) if res.projects else "keine"
    lines = [f"Zurückgespielt: Operator-Tresor und {_projects(len(res.projects))} ({names}), {res.files} "
             f"Dateien, Manifest und Hashes geprüft (Sicherung vom {res.created_utc}, Ariadne "
             f"{term_safe(res.ariadne_version, max_len=40)})."]
    if res.config_added:
        lines.append("  Konfiguration ergänzt: "
                     + ", ".join(term_safe(x, max_len=80) for x in res.config_added))
    if res.config_kept:
        lines.append("  Konfiguration behalten (schon vorhanden): "
                     + ", ".join(term_safe(x, max_len=80) for x in res.config_kept))
    lines += _heads(res.chain_heads, res.head_seqs, res.projects)
    if res.verified:
        for slug in res.projects:
            if slug in res.verified:
                lines.append(f"  Kette {slug}: {'in Ordnung' if res.verified[slug] else 'FEHLER'}")
    else:
        first = res.projects[0] if res.projects else "SLUG"
        unlock = "ariadne-mac unlock (oder ssh -t kali-sl unlock)" if remote else "ariadne unlock"
        lines.append("Den Kettenkopf oben mit dem Wert vergleichen, den ariadne-mac stop bzw. ariadne "
                     "backup beim Sichern zeigte.")
        lines.append(f"Ketten noch nicht geprüft. Weiter mit {unlock}, dann in der Kali ariadne start "
                     f"{first} und ariadne verify: verify nennt diesen Kopf als «Kettenkopf beim letzten "
                     f"Schliessen … in der Kette» und muss «in Ordnung» melden (der aktuelle Kettenkopf "
                     f"ist nach dem Öffnen immer neuer).")
    return lines
