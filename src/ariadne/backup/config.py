"""Empfänger der Sicherung (Vertrag v0.1-Server 3.5 und 3.7, Konzept Fernzugriff 6.2).

Zwei Quellen, beide unter ``~/.config/ariadne``:

* ``config.toml``, Tabelle ``[backup]``, Schlüssel ``recipients = ["age1…", …]``;
* ``backup-recipients.txt``: ein Empfänger pro Zeile, leere Zeilen und Zeilen mit ``#`` am Anfang
  zählen nicht (wie ``age -R``). ``kali-setup.sh`` schreibt diese Datei mit Rechten 0600.

Nur klassische X25519-Empfänger (``age1…``): Das age-Paket der Kali kann älter sein als das auf
dem Mac, Plugins und SSH-Schlüssel gelten nicht. Anders als bei anderen Einstellungen fällt ein
ungültiger Empfänger **nicht** still auf den Standard zurück: Eine Sicherung, die der Mac-Schlüssel
wegen eines Tippfehlers nicht öffnen kann, wäre ein stiller Datenverlust. Darum Abbruch mit
``bad_recipient`` und Zeilennummer, ebenso wenn eine der Dateien für Gruppe oder andere
beschreibbar ist (dann könnte ein anderer Benutzer einen eigenen Empfänger unterschieben). Ohne
Empfänger: ``no_recipients``, nie unverschlüsselt.
"""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from pyrage import x25519

from ariadne.backup.model import BackupError
from ariadne.paths import Paths

__all__ = ["RECIPIENTS_FILE", "MAX_RECIPIENTS", "Recipients", "load_recipients", "parse_recipient_lines",
           "valid_recipient"]

RECIPIENTS_FILE = "backup-recipients.txt"
MAX_RECIPIENTS = 32
MAX_FILE = 64 << 10
MAX_CONFIG = 1 << 20


@dataclass(frozen=True)
class Recipients:
    recipients: tuple[str, ...]
    warnings: tuple[str, ...] = field(default_factory=tuple)
    sources: tuple[str, ...] = field(default_factory=tuple)  # «config.toml», «backup-recipients.txt»


def valid_recipient(text: str) -> bool:
    """Klassischer age-X25519-Empfänger (``age1`` plus Bech32), keine Plugins, kein SSH."""
    if not isinstance(text, str) or not text.startswith("age1") or len(text) > 100:
        return False
    try:
        x25519.Recipient.from_str(text)
    except Exception:  # noqa: BLE001 (pyrage.RecipientError und Verwandte)
        return False
    return True


def _bad(source: str, where: str) -> BackupError:
    return BackupError(
        "bad_recipient",
        f"Empfänger ungültig ({source}, {where}). Erlaubt sind nur X25519-Empfänger «age1…» "
        "(keine Plugins, keine SSH-Schlüssel). Die Sicherung wurde nicht geschrieben.")


def _read_checked(path: Path, max_size: int, source: str) -> bytes | None:
    """Liest eine Konfigurationsdatei des Benutzers; ``None``, wenn sie fehlt.

    Symlinks, fremde und für andere beschreibbare Dateien führen zu ``bad_recipient``: Wer
    Empfänger unterschieben kann, liest jede künftige Sicherung.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise BackupError("bad_recipient",
                          f"{source} nicht lesbar (Symlink oder keine Rechte). "
                          "Die Sicherung wurde nicht geschrieben.") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise BackupError("bad_recipient", f"{source} ist keine reguläre Datei")
        if st.st_uid != os.getuid():
            raise BackupError("bad_recipient", f"{source} gehört nicht dem Benutzer")
        if st.st_mode & 0o022:
            raise BackupError("bad_recipient",
                              f"{source} ist für Gruppe oder andere beschreibbar (chmod 600 {source})")
        if st.st_size > max_size:
            raise BackupError("bad_recipient", f"{source} ist zu gross")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1 << 16)
            if not chunk:
                break
            chunks.append(chunk)
            if sum(len(c) for c in chunks) > max_size:
                raise BackupError("bad_recipient", f"{source} ist zu gross")
        return b"".join(chunks)
    finally:
        os.close(fd)


def parse_recipient_lines(text: str, source: str = RECIPIENTS_FILE) -> list[str]:
    """Zeilen im Format von ``age -R``. Wirft ``bad_recipient`` mit der Zeilennummer."""
    out: list[str] = []
    for no, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not valid_recipient(line):
            raise _bad(source, f"Zeile {no}")
        out.append(line)
    return out


def _from_config(path: Path) -> tuple[list[str], list[str]]:
    data = _read_checked(path, MAX_CONFIG, "config.toml")
    if data is None:
        return [], []
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        # Eine kaputte config.toml betrifft auch andere Teile; hier zählt nur [backup].
        return [], ["config.toml nicht lesbar, [backup] recipients nicht berücksichtigt"]
    table = doc.get("backup")
    if table is None:
        return [], []
    if not isinstance(table, dict):
        raise _bad("config.toml", "[backup] ist keine Tabelle")
    recips = table.get("recipients", [])
    if not isinstance(recips, list):
        raise _bad("config.toml", "[backup] recipients ist keine Liste")
    out: list[str] = []
    for i, r in enumerate(recips, start=1):
        if not isinstance(r, str) or not valid_recipient(r.strip()):
            raise _bad("config.toml", f"[backup] recipients Eintrag {i}")
        out.append(r.strip())
    return out, []


def load_recipients(paths: Paths) -> Recipients:
    """Alle Empfänger aus beiden Quellen, ohne Doppelte, in fester Reihenfolge.

    Wirft ``no_recipients`` ohne Empfänger, ``bad_recipient`` bei einem ungültigen.
    """
    warnings: list[str] = []
    sources: list[str] = []
    cfg, warn = _from_config(paths.config_file)
    warnings += warn
    if cfg:
        sources.append("config.toml")
    raw = _read_checked(paths.config_dir / RECIPIENTS_FILE, MAX_FILE, RECIPIENTS_FILE)
    listed: list[str] = []
    if raw is not None:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise _bad(RECIPIENTS_FILE, "kein UTF-8") from exc
        listed = parse_recipient_lines(text)
        if listed:
            sources.append(RECIPIENTS_FILE)
    seen: set[str] = set()
    out: list[str] = []
    for r in cfg + listed:
        if r not in seen:
            seen.add(r)
            out.append(r)
    if not out:
        raise BackupError(
            "no_recipients",
            f"Keine Empfänger für die Sicherung. Öffentliche Schlüssel (age1…) eintragen in "
            f"~/.config/ariadne/{RECIPIENTS_FILE} (eine Zeile pro Schlüssel, Rechte 600) oder "
            f"[backup] recipients in config.toml. Unverschlüsselt sichert Ariadne nie.")
    if len(out) > MAX_RECIPIENTS:
        raise BackupError("bad_recipient", f"Zu viele Empfänger (höchstens {MAX_RECIPIENTS})")
    return Recipients(tuple(out), tuple(warnings), tuple(sources))
