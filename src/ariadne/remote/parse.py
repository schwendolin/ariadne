"""Reine Parser für ``ariadne remote check`` (R10): keine Programme, kein Netz, keine Dateien.

* :func:`parse_authorized_keys`: Zeilen aus ``authorized_keys`` mit Optionen (Werte in
  Anführungszeichen dürfen Kommas, Leerzeichen und ``\\"`` enthalten).
* :func:`key_fingerprint`: ``SHA256:…`` wie ``ssh-keygen -lf`` aus dem Base64-Teil eines Schlüssels.
* :func:`parse_sshd_t`: Ausgabe von ``sshd -T`` (Schlüssel klein, Werte pro Schlüssel gesammelt).
* :func:`parse_sshd_config`: eine ``sshd_config``-Datei (Drop-in), erster Wert gilt wie bei sshd.
* :func:`parse_marker`: Marker des Einrichtungsskripts (``schluessel=wert``).
* :func:`parse_openssh_version`: ``OpenSSH_9.6p1 …`` → ``(9, 6)``.
* :func:`parse_tailscale_prefs`: JSON aus ``tailscale debug prefs``.
* :func:`tcp_listeners`: lauschende Adressen eines Ports aus ``/proc/net/tcp`` und ``tcp6``.

Alles, was hier gelesen wird, kann von einem Angreifer mit den Rechten des Benutzers stammen;
die Parser sind darum linear, ohne reguläre Ausdrücke über fremden Text und mit Grenzen.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
from dataclasses import dataclass

from ariadne.web.peer import parse_proc_net

__all__ = [
    "AuthKey",
    "KEY_TYPES",
    "parse_authorized_keys",
    "pubkey_fingerprint",
    "split_options",
    "key_fingerprint",
    "parse_sshd_t",
    "parse_sshd_config",
    "parse_marker",
    "parse_openssh_version",
    "parse_tailscale_prefs",
    "tcp_listeners",
    "is_loopback",
    "MAX_LINE",
]

MAX_LINE = 16384  # längere Zeilen ignoriert auch sshd (8 kB), mehr lesen wir nie
_LISTEN = 0x0A

KEY_TYPES = frozenset({
    "ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com",
    "sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com",
    "ssh-rsa", "ssh-rsa-cert-v01@openssh.com", "rsa-sha2-256", "rsa-sha2-512",
    "ssh-dss", "ssh-dss-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
})


@dataclass(frozen=True)
class AuthKey:
    """Eine Schlüsselzeile. ``options`` in der Reihenfolge der Datei, Namen klein geschrieben;
    ``bad_options`` ist wahr, wenn sich die Optionen nicht sauber lesen liessen."""

    line_no: int
    options: tuple[tuple[str, str | None], ...]
    keytype: str
    blob: str
    comment: str
    bad_options: bool = False

    def has(self, name: str) -> bool:
        return any(n == name for n, _ in self.options)

    def values(self, name: str) -> list[str | None]:
        return [v for n, v in self.options if n == name]

    @property
    def fingerprint(self) -> str | None:
        return key_fingerprint(self.blob)


def _is_space(ch: str) -> bool:
    return ch in " \t"


def split_options(text: str) -> tuple[list[tuple[str, str | None]], int, bool]:
    """Liest den Optionsteil am Anfang von ``text``.

    Gibt die Optionen, die Position nach dem Optionsteil und ``ok`` zurück. Ein Wert steht in
    Anführungszeichen und darf ``\\"`` enthalten (wie ``sshd``); ein Komma trennt Optionen."""
    opts: list[tuple[str, str | None]] = []
    i, n = 0, len(text)
    ok = True
    while i < n and not _is_space(text[i]):
        start = i
        while i < n and text[i] not in ',="' and not _is_space(text[i]):
            i += 1
        name = text[start:i].lower()
        value: str | None = None
        if i < n and text[i] == "=":
            i += 1
            if i >= n or text[i] != '"':
                ok = False
                vstart = i
                while i < n and text[i] != "," and not _is_space(text[i]):
                    i += 1
                value = text[vstart:i]
            else:
                i += 1
                buf: list[str] = []
                closed = False
                while i < n:
                    ch = text[i]
                    if ch == "\\" and i + 1 < n and text[i + 1] == '"':
                        buf.append('"')
                        i += 2
                        continue
                    if ch == '"':
                        closed = True
                        i += 1
                        break
                    buf.append(ch)
                    i += 1
                if not closed:
                    ok = False
                value = "".join(buf)
        elif i < n and text[i] == '"':
            ok = False
            i += 1
        if not name:
            ok = False
        opts.append((name, value))
        if i < n and text[i] == ",":
            i += 1
            if i >= n or _is_space(text[i]):
                ok = False
        elif i < n and not _is_space(text[i]):
            ok = False
            i += 1
    return opts, i, ok


def parse_authorized_keys(text: str) -> list[AuthKey]:
    """Alle Schlüsselzeilen (Kommentare und Leerzeilen übersprungen). Eine Zeile, die sich nicht
    lesen lässt, erscheint trotzdem (``keytype`` leer bzw. ``bad_options``): Sie zählt als Schlüssel,
    denn sshd könnte sie anders lesen als wir."""
    out: list[AuthKey] = []
    for no, raw in enumerate(text.splitlines(), start=1):
        line = raw[:MAX_LINE].strip(" \t\r")
        if not line or line.startswith("#"):
            continue
        first = line.split(None, 1)[0]
        options: list[tuple[str, str | None]] = []
        ok = True
        rest = line
        if first not in KEY_TYPES:
            options, pos, ok = split_options(line)
            rest = line[pos:].lstrip(" \t")
        parts = rest.split(None, 2)
        keytype = parts[0] if parts else ""
        blob = parts[1] if len(parts) > 1 else ""
        comment = parts[2] if len(parts) > 2 else ""
        if keytype not in KEY_TYPES:
            ok = False
        out.append(AuthKey(no, tuple(options), keytype, blob, comment, bad_options=not ok))
    return out


def key_fingerprint(blob: str) -> str | None:
    """``SHA256:<base64 ohne =>`` des Schlüssels, wie ``ssh-keygen -l`` ihn zeigt."""
    try:
        raw = base64.b64decode(blob.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def pubkey_fingerprint(text: str) -> tuple[str, str] | None:
    """Typ und Fingerprint aus dem Inhalt einer ``.pub``-Datei (erste Schlüsselzeile)."""
    for key in parse_authorized_keys(text):
        fp = key.fingerprint
        if key.keytype and fp:
            return key.keytype, fp
    return None


def parse_sshd_t(text: str) -> dict[str, list[str]]:
    """``sshd -T``: jede Zeile ``schlüssel wert``; wiederholte Schlüssel sammeln sich."""
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw[:MAX_LINE].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        out.setdefault(key.lower(), []).append(value.strip())
    return out


def parse_sshd_config(text: str) -> dict[str, list[str]]:
    """Eine ``sshd_config``-Datei ohne ``Match``: Schlüssel klein, Werte in Dateireihenfolge.

    Bei sshd gilt für die meisten Schlüssel der erste Wert; ``Match``-Blöcke werden nicht
    ausgewertet, sondern unter dem Schlüssel ``match`` gezählt."""
    out: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw[:MAX_LINE].strip()
        if not line or line.startswith("#"):
            continue
        cut = len(line)
        for i, ch in enumerate(line):
            if ch in " \t=":
                cut = i
                break
        key, value = line[:cut], line[cut:]
        value = value.strip(" \t")
        if value.startswith("="):
            value = value[1:].strip(" \t")
        out.setdefault(key.lower(), []).append(value)
    return out


def parse_marker(text: str) -> dict[str, str]:
    """Marker des Einrichtungsskripts: ``schlüssel=wert`` pro Zeile, ``#`` Kommentar."""
    out: dict[str, str] = {}
    for raw in text.splitlines()[:64]:
        line = raw[:1024].strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out.setdefault(key.strip().lower(), value.strip())
    return out


def parse_openssh_version(text: str) -> tuple[int, int] | None:
    """``OpenSSH_9.6p1 Ubuntu-3, OpenSSL …`` → ``(9, 6)``; sonst ``None``."""
    idx = text.find("OpenSSH_")
    if idx < 0:
        return None
    rest = text[idx + len("OpenSSH_"):idx + 40]
    major = ""
    i = 0
    while i < len(rest) and rest[i].isdigit():
        major += rest[i]
        i += 1
    if not major or i >= len(rest) or rest[i] != ".":
        return None
    i += 1
    minor = ""
    while i < len(rest) and rest[i].isdigit():
        minor += rest[i]
        i += 1
    if not minor:
        return None
    return int(major), int(minor)


def parse_tailscale_prefs(text: str) -> dict[str, object] | None:
    """JSON-Objekt aus ``tailscale debug prefs`` oder ``None``."""
    try:
        data = json.loads(text[: 1 << 20])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def tcp_listeners(tcp: str, tcp6: str, port: int) -> list[str]:
    """Lokale Adressen aller Sockets, die auf ``port`` lauschen (``/proc/net/tcp`` und ``tcp6``)."""
    out: list[str] = []
    for text in (tcp, tcp6):
        for e in parse_proc_net(text):
            if e.state == _LISTEN and e.local[1] == port:
                out.append(e.local[0])
    return sorted(set(out))
