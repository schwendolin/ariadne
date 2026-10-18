"""Befehlsbibliothek der Denkanstösse (E68, Architektur 6.1, ``docs/web-api.md`` 18.6).

Vorlagen stehen nur hier (nie im Browser) und haben nur typisierte Platzhalter ``{slot}``; der Typ
jedes Slots steht in :data:`SLOTS`, sein Encoder in :mod:`ariadne.rules.encoders`. Werkzeugwissen
steckt nur hier und in den Erkennern (:mod:`ariadne.rules.commands`), nie in den Regeln.

**Lint beim Laden** (:func:`lint`, läuft beim Import für jede Vorlage): nur druckbares ASCII,
keine Zeilenumbrüche, einzelne Leerzeichen, nur bekannte Slots, fester Text ohne Shell-Metazeichen
(ausser ``''`` für ein leeres Argument), ein Slot vom Typ ``words`` steht allein als Wort, zwei Slots
im selben Wort sind durch festen Text getrennt, das erste Wort (nach ``sudo``) ist das Werkzeug.

**Rendern** (:func:`render`): Erst wenn jeder Wert seinen Encoder besteht, entsteht ein Befehl.
Danach prüft :func:`render` noch einmal mit ``shlex.split``, dass der Befehl genau in die erwarteten
Wörter zerfällt (zweite Schicht); sonst gibt es keinen Befehl. Ein Befehl endet nie mit einem
Zeilenumbruch.
"""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ariadne.rules.encoders import PLACEHOLDER_TYPES, SHELL_META, Encoded, Scope, encode
from ariadne.rules.text import Parts, vis

__all__ = ["SLOTS", "Template", "TEMPLATES", "lint", "render", "skeleton", "TemplateError"]

# Slot -> (Platzhaltertyp, Anzeige in der UI)
SLOTS: dict[str, tuple[str, str]] = {
    "host.ip": ("ip", "IP"),
    "service.port": ("port", "Port"),
    "service.url": ("url", "URL"),
    "service.product": ("words", "Produkt"),
    "service.version": ("word", "Version"),
}

_SLOT_RE = re.compile(r"\{([a-z]+\.[a-z]+)\}")
_SENTINEL = "QQSLOT{}QQ"
_SENTINEL_RE = re.compile(r"QQSLOT(\d+)QQ")


class TemplateError(ValueError):
    """Eine Vorlage der Bibliothek verletzt den Lint (Programmfehler, fällt beim Import auf)."""


@dataclass(frozen=True)
class Template:
    """Eine Vorlage. ``text6``: Variante für IPv6-Ziele (``nmap -6``); ``None``: wie ``text``."""

    template_id: str
    tool: str
    label: str
    text: str
    text6: str | None = None


def _t(template_id: str, tool: str, label: str, text: str, text6: str | None = None) -> Template:
    return Template(template_id, tool, label, text, text6)


def _nmap(template_id: str, label: str, args: str) -> Template:
    return _t(template_id, "nmap", label, f"nmap {args}", f"nmap -6 {args}")


_LIBRARY = [
    # Anonymer Zugriff (PZ-AUTH-ANON)
    _nmap("nmap-ftp-anon", "nmap-Skript ftp-anon", "-p {service.port} --script ftp-anon {host.ip}"),
    _t("ftp-client", "ftp", "ftp-Client, Benutzer anonymous", "ftp {host.ip} {service.port}"),
    _t("rpcclient-null", "rpcclient", "rpcclient mit Null-Session", "rpcclient -U '' -N {host.ip}"),
    _t("nxc-smb-null", "nxc", "NetExec mit leerem Konto", "nxc smb {host.ip} -u '' -p ''"),
    # SMB-Shares (PZ-SMB-SHARES)
    _t(
        "smbclient-list",
        "smbclient",
        "smbclient: Shares ohne Anmeldung auflisten",
        "smbclient -N -L //{host.ip}",
    ),
    _t("smbmap", "smbmap", "smbmap: Shares und Rechte", "smbmap -H {host.ip}"),
    _nmap(
        "nmap-smb-enum-shares",
        "nmap-Skript smb-enum-shares",
        "-p {service.port} --script smb-enum-shares {host.ip}",
    ),
    # NFS (PZ-NFS-EXPORTS)
    _t("showmount", "showmount", "showmount: Exporte auflisten", "showmount -e {host.ip}"),
    _nmap("nmap-nfs-showmount", "nmap-Skript nfs-showmount", "-p 111 --script nfs-showmount {host.ip}"),
    # Webinhalt (PZ-WEB-INHALT)
    _t("curl-head", "curl", "curl: Antwort mit Kopfzeilen", "curl -i {service.url}"),
    _t("whatweb", "whatweb", "whatweb: Technik erkennen", "whatweb {service.url}"),
    _t(
        "gobuster-dir",
        "gobuster",
        "gobuster: Verzeichnisse raten",
        "gobuster dir -u {service.url} -w /usr/share/wordlists/dirb/common.txt",
    ),
    _t("nikto", "nikto", "nikto: bekannte Probleme", "nikto -h {service.url}"),
    # Version recherchieren (PZ-VULN-RECHERCHE)
    _t("searchsploit", "searchsploit", "searchsploit", "searchsploit {service.product} {service.version}"),
    # Ports (PZ-PORTS-TCP, PZ-PORTS-UDP)
    _nmap("nmap-full-tcp", "nmap: alle TCP-Ports", "-p- -T4 {host.ip}"),
    _t(
        "nmap-udp-top",
        "nmap",
        "nmap: häufigste UDP-Ports (braucht root)",
        "sudo nmap -sU --top-ports 100 {host.ip}",
        "sudo nmap -6 -sU --top-ports 100 {host.ip}",
    ),
    # Standardkonten (PZ-CRED-DEFAULT)
    _nmap(
        "nmap-http-default-accounts",
        "nmap-Skript http-default-accounts",
        "-p {service.port} --script http-default-accounts {host.ip}",
    ),
    _t("vncviewer", "vncviewer", "vncviewer", "vncviewer {host.ip}::{service.port}"),
    _t("telnet-client", "telnet", "telnet-Client", "telnet {host.ip} {service.port}"),
    _t(
        "snmpwalk-public",
        "snmpwalk",
        "snmpwalk mit Community public",
        "snmpwalk -v2c -c public {host.ip}:{service.port}",
        "snmpwalk -v2c -c public udp6:{host.ip}",
    ),
    # SMTP-Benutzer (PZ-SMTP-USER)
    _t(
        "smtp-user-enum-vrfy",
        "smtp-user-enum",
        "smtp-user-enum mit VRFY",
        "smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt "
        "-t {host.ip} -p {service.port}",
    ),
    _nmap(
        "nmap-smtp-enum-users",
        "nmap-Skript smtp-enum-users",
        "-p {service.port} --script smtp-enum-users {host.ip}",
    ),
    # Datenbanken (PZ-DB-ZUGRIFF)
    _t(
        "mysql-root-nopass",
        "mysql",
        "mysql-Client als root ohne Passwort",
        "mysql -h {host.ip} -P {service.port} -u root --skip-ssl",
    ),
    _nmap(
        "nmap-mysql-empty-password",
        "nmap-Skript mysql-empty-password",
        "-p {service.port} --script mysql-empty-password {host.ip}",
    ),
    _t("psql-postgres", "psql", "psql als postgres", "psql -h {host.ip} -p {service.port} -U postgres"),
    _nmap(
        "nmap-ms-sql-empty-password",
        "nmap-Skript ms-sql-empty-password",
        "-p {service.port} --script ms-sql-empty-password {host.ip}",
    ),
    _t("redis-info", "redis-cli", "redis-cli info", "redis-cli -h {host.ip} -p {service.port} info"),
    _nmap(
        "nmap-mongodb-info", "nmap-Skript mongodb-info", "-p {service.port} --script mongodb-info {host.ip}"
    ),
]


def skeleton(text: str) -> tuple[list[str], list[str]]:
    """Wörter der Vorlage mit Platzhaltern als Sentinel und die Slots in Reihenfolge."""
    slots: list[str] = []

    def sub(m: re.Match[str]) -> str:
        slots.append(m.group(1))
        return _SENTINEL.format(len(slots) - 1)

    return shlex.split(_SLOT_RE.sub(sub, text)), slots


def lint(t: Template) -> None:
    """Prüft eine Vorlage (siehe Moduldoku); wirft :class:`TemplateError`."""
    if not re.fullmatch(r"[a-z0-9-]{1,40}", t.template_id) or not t.label or not t.tool:
        raise TemplateError(f"{t.template_id}: Kopf ungültig")
    for text in (t.text, t.text6):
        if text is None:
            continue
        where = f"{t.template_id}: {text!r}"
        if not text.isascii() or not text.isprintable():
            raise TemplateError(f"{where}: nur druckbares ASCII")
        if text != text.strip() or "  " in text:
            raise TemplateError(f"{where}: Leerzeichen")
        literal = _SLOT_RE.sub("", text)
        if "{" in literal or "}" in literal:
            raise TemplateError(f"{where}: Klammer ausserhalb eines Slots")
        if any(ch in SHELL_META for ch in literal.replace("''", "")):
            raise TemplateError(f"{where}: Shell-Metazeichen im festen Text")
        if "QQSLOT" in literal:
            raise TemplateError(f"{where}: reservierter Text")
        tokens, slots = skeleton(text)
        for s in slots:
            if s not in SLOTS or SLOTS[s][0] not in PLACEHOLDER_TYPES:
                raise TemplateError(f"{where}: unbekannter Slot {s}")
        for tok in tokens:
            found = _SENTINEL_RE.findall(tok)
            if any(SLOTS[slots[int(i)]][0] == "words" for i in found) and tok != _SENTINEL.format(found[0]):
                raise TemplateError(f"{where}: Slot vom Typ words muss allein stehen")
            if "QQQQSLOT" in tok:
                raise TemplateError(f"{where}: Slots ohne Trenner")
        words = tokens[1:] if tokens and tokens[0] == "sudo" else tokens
        if not words or os.path.basename(words[0]) != t.tool:
            raise TemplateError(f"{where}: Werkzeug passt nicht")


def _check_library() -> dict[str, Template]:
    out: dict[str, Template] = {}
    for t in _LIBRARY:
        lint(t)
        if t.template_id in out:
            raise TemplateError(f"{t.template_id}: doppelt")
        out[t.template_id] = t
    return out


TEMPLATES: dict[str, Template] = _check_library()


def _shown(raw: object) -> tuple[str, bool]:
    if isinstance(raw, int) and not isinstance(raw, bool):
        return str(raw), False
    return vis(raw if isinstance(raw, str) else str(raw))


def render(t: Template, values: Mapping[str, object], scope: Scope, *, ipv6: bool = False) -> dict[str, Any]:
    """``CommandTemplate`` (web-api.md 18.6) für die Vorlage ``t`` mit den Rohwerten ``values``.

    ``values`` enthält pro Slot den Rohwert aus der Projektion (bekannte Secrets schon maskiert).
    Fehlt ein Slot, gilt er als ungültig."""
    text = t.text6 if ipv6 and t.text6 else t.text
    tokens, slots = skeleton(text)
    order: list[str] = list(dict.fromkeys(slots))
    enc: dict[str, Encoded] = {}
    out_values: list[dict[str, Any]] = [
        {
            "slot": "tool",
            "type": "word",
            "label": "Werkzeug",
            "value": t.tool,
            "ctrl": False,
            "target": False,
            "safe": True,
        },
    ]
    blocked: str | None = None
    for slot in order:
        ptype, label = SLOTS[slot]
        raw = values.get(slot)
        e = encode(ptype, raw, scope) if raw is not None else Encoded(False, None, "invalid")
        enc[slot] = e
        shown, ctrl = _shown(raw if raw is not None else "")
        out_values.append(
            {
                "slot": slot,
                "type": ptype,
                "label": label,
                "value": shown,
                "ctrl": ctrl,
                "target": True,
                "safe": e.safe,
            }
        )
        if not e.safe and blocked is None:
            blocked = e.reason or "invalid"
    base = {"template_id": t.template_id, "tool": t.tool, "label": t.label, "values": out_values}
    if blocked is not None:
        return {**base, "rendered": False, "command": None, "parts": [], "blocked_reason": blocked}
    # Befehl zusammensetzen, Teile markieren, erwartete Wörter bilden
    parts = Parts()
    pos = 0
    for m in _SLOT_RE.finditer(text):
        parts.lit(text[pos : m.start()])
        parts.items.append((str(enc[m.group(1)].text), True))
        pos = m.end()
    parts.lit(text[pos:])
    command = parts.text
    expected: list[str] = []
    for tok in tokens:
        idx = _SENTINEL_RE.findall(tok)
        if len(idx) == 1 and tok == _SENTINEL.format(idx[0]) and SLOTS[slots[int(idx[0])]][0] == "words":
            expected.extend(str(enc[slots[int(idx[0])]].text).split(" "))
            continue
        expected.append(_SENTINEL_RE.sub(lambda m: str(enc[slots[int(m.group(1))]].text), tok))
    try:
        ok = shlex.split(command) == expected
    except ValueError:
        ok = False
    if not ok or command.endswith(("\n", "\r")):  # zweite Schicht; mit Lint und Encodern unerreichbar
        return {**base, "rendered": False, "command": None, "parts": [], "blocked_reason": "invalid"}
    return {**base, "rendered": True, "command": command, "parts": parts.json(), "blocked_reason": None}
