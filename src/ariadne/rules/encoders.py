"""Kontext-Encoder für die Platzhalter der Befehlsvorlagen (E68, Architektur 6.1 Punkte 1 bis 6,
``docs/web-api.md`` 18.6).

Befehlsvorlagen sind die gefährlichste Senke im System: Ihre Platzhalter kommen aus Zieldaten, und
der Mensch kopiert das Ergebnis in eine Shell. Jeder Platzhalter hat darum einen Typ, und der Encoder
des Typs **prüft und formt nie um** (einzige Ausnahme: die kanonische Form einer IP-Adresse bzw. eines
Netzes und die Dezimalform eines Ports). Besteht ein Wert die Prüfung nicht, wird die Vorlage nicht
gerendert; die Oberfläche zeigt dann nur die Einzelwerte.

Reihenfolge der Prüfung (der erste Grund zählt):

1. ``newline``: LF, CR, NEL, U+2028, U+2029
2. ``control``: C0, DEL, C1, Bidi-, Zero-Width- und Tag-Zeichen, andere Formatzeichen
3. ``non_ascii``: alles ausserhalb von druckbarem ASCII (Homoglyphen, ``•`` aus maskierten Secrets)
4. ``shell_meta``: Anführungszeichen, Backtick, ``$ ; & | < > ( ) { } [ ] * ? ! \\ #``, dazu ``~`` und
   ``^`` (Glob-Operatoren der zsh mit ``EXTENDED_GLOB``) und Leerraum an falscher Stelle
5. ``invalid``: passt nicht zum Typ (Zeichenvorrat, Länge, Bereich, führender Bindestrich)
6. ``out_of_scope``: Adresse, Netz oder Name ohne Scope-Urteil ``in``

Strenger als die Tabelle in web-api.md 18.6 (bewusst, fail-closed): ``~`` ist in URLs gesperrt
(zsh-Glob), Werte der Typen ``word``, ``words``, ``user`` und ``share`` dürfen nicht mit ``-`` beginnen
(sonst würde das Werkzeug sie als Option lesen), ``$`` in ``share`` nur als letztes Zeichen
(``C$``, ``IPC$``; mitten im Wort wäre es eine Variable), IPv6-Adressen ohne Zonen-ID (``%eth0``).
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, get_args

__all__ = [
    "PlaceholderType",
    "BlockedReason",
    "PLACEHOLDER_TYPES",
    "Encoded",
    "Scope",
    "encode",
    "first_problem",
    "SHELL_META",
]

PlaceholderType = Literal["ip", "port", "hostname", "cidr", "url", "word", "words", "path", "user", "share"]
BlockedReason = Literal["shell_meta", "control", "newline", "non_ascii", "invalid", "out_of_scope"]
PLACEHOLDER_TYPES: frozenset[str] = frozenset(get_args(PlaceholderType))

# Shell-Metazeichen (web-api.md 18.6) plus ``~`` und ``^`` (zsh-Globbing mit EXTENDED_GLOB).
SHELL_META = frozenset("'\"`$;&|<>(){}[]*?!\\#~^")
_NEWLINES = frozenset("\n\r\x85\u2028\u2029")

_WORD = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_USER = re.compile(r"[A-Za-z0-9._-]{1,64}")
_SHARE = re.compile(r"[A-Za-z0-9._-]{1,79}\$?")
_PATH = re.compile(r"/[A-Za-z0-9._/+-]{0,254}")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_URL_CHARS = re.compile(r"[A-Za-z0-9._:/@=%+-]+")
_PORT = re.compile(r"[1-9][0-9]{0,4}")
_WORDS_MAX = 6


@dataclass(frozen=True)
class Scope:
    """Scope-Urteile für den Encoder (E68 Punkt 5): nur Werte mit Urteil ``in`` sind erlaubt.

    ``ip`` bekommt die kanonische Adresse, ``name`` den kleingeschriebenen Namen, ``net`` ein Netz.
    Fehlt eine Funktion, gilt der Wert als ausserhalb (fail-closed)."""

    ip: Callable[[str], str | None] | None = None
    name: Callable[[str], str | None] | None = None
    net: Callable[[ipaddress.IPv4Network | ipaddress.IPv6Network], bool] | None = None


@dataclass(frozen=True)
class Encoded:
    """Ergebnis eines Encoders: ``text`` ist der Wert für den Befehl (nur wenn ``safe``)."""

    safe: bool
    text: str | None
    reason: BlockedReason | None


def _is_control(ch: str) -> bool:
    cp = ord(ch)
    if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
        return True
    if 0xE0000 <= cp <= 0xE007F:  # Tag-Zeichen
        return True
    return unicodedata.category(ch) in ("Cf", "Cc", "Cs", "Co", "Cn", "Zl", "Zp")


def first_problem(text: str, *, spaces: bool = False) -> BlockedReason | None:
    """Erster Grund aus den Stufen 1 bis 4, der gegen ``text`` spricht (``None``: alles druckbares
    ASCII ohne Metazeichen). ``spaces``: einzelne Leerzeichen zwischen Wörtern sind erlaubt."""
    if any(ch in _NEWLINES for ch in text):
        return "newline"
    if any(_is_control(ch) for ch in text):
        return "control"
    if not text.isascii():
        return "non_ascii"
    if any(ch in SHELL_META for ch in text):
        return "shell_meta"
    if " " in text:
        if not spaces:
            return "shell_meta"
        if text.startswith(" ") or text.endswith(" ") or "  " in text:
            return "shell_meta"
    return None


def _ok(text: str) -> Encoded:
    return Encoded(True, text, None)


def _bad(reason: BlockedReason) -> Encoded:
    return Encoded(False, None, reason)


def _enc_port(raw: object) -> Encoded:
    if isinstance(raw, bool):
        return _bad("invalid")
    if isinstance(raw, int):
        return _ok(str(raw)) if 1 <= raw <= 65535 else _bad("invalid")
    assert isinstance(raw, str)
    if not _PORT.fullmatch(raw) or int(raw) > 65535:
        return _bad("invalid")
    return _ok(raw)


def _enc_ip(raw: str, scope: Scope) -> Encoded:
    if "%" in raw:  # Zonen-ID: ipaddress nimmt dort beliebigen Text an
        return _bad("invalid")
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return _bad("invalid")
    canon = addr.compressed
    if scope.ip is None or scope.ip(canon) != "in":
        return _bad("out_of_scope")
    return _ok(canon)


def _enc_cidr(raw: str, scope: Scope) -> Encoded:
    if "%" in raw or "/" not in raw:
        return _bad("invalid")
    try:
        net = ipaddress.ip_network(raw, strict=True)
    except ValueError:
        return _bad("invalid")
    if scope.net is None or not scope.net(net):
        return _bad("out_of_scope")
    return _ok(net.compressed)


def _enc_hostname(raw: str, scope: Scope) -> Encoded:
    if len(raw) > 253 or raw.startswith("-"):
        return _bad("invalid")
    labels = raw.split(".")
    if not all(_LABEL.fullmatch(lb) for lb in labels):
        return _bad("invalid")
    if scope.name is None or scope.name(raw.lower()) != "in":
        return _bad("out_of_scope")
    return _ok(raw)


def _enc_url(raw: str, scope: Scope) -> Encoded:
    if not _URL_CHARS.fullmatch(raw):
        return _bad("invalid")
    m = re.fullmatch(r"(https?)://([^/]+)(/.*)?", raw)
    if m is None:
        return _bad("invalid")
    authority = m.group(2)
    if "@" in authority:  # ohne Benutzer und Passwort
        return _bad("invalid")
    host, port = authority, None
    if host.count(":") == 1:
        host, port = host.split(":")
    if port is not None and _enc_port(port).reason is not None:
        return _bad("invalid")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        host_ok = _enc_hostname(host, scope)
        return _ok(raw) if host_ok.safe else _bad(host_ok.reason or "invalid")
    if addr.version != 4:  # IPv6 bräuchte Klammern (Glob-Zeichen); gesperrt
        return _bad("invalid")
    if scope.ip is None or scope.ip(addr.compressed) != "in":
        return _bad("out_of_scope")
    if addr.compressed != host:
        return _bad("invalid")
    return _ok(raw)


def _enc_word(raw: str) -> Encoded:
    if raw.startswith("-") or not _WORD.fullmatch(raw):
        return _bad("invalid")
    return _ok(raw)


def _enc_words(raw: str) -> Encoded:
    parts = raw.split(" ")
    if not 1 <= len(parts) <= _WORDS_MAX:
        return _bad("invalid")
    if any(p.startswith("-") or not _WORD.fullmatch(p) for p in parts):
        return _bad("invalid")
    return _ok(raw)


def _enc_path(raw: str) -> Encoded:
    if not _PATH.fullmatch(raw) or ".." in raw.split("/"):
        return _bad("invalid")
    return _ok(raw)


def _enc_user(raw: str) -> Encoded:
    if raw.startswith("-") or not _USER.fullmatch(raw):
        return _bad("invalid")
    return _ok(raw)


def _enc_share(raw: str) -> Encoded:
    if raw.startswith("-") or len(raw) > 80 or not _SHARE.fullmatch(raw):
        return _bad("invalid")
    return _ok(raw)


def encode(ptype: str, raw: object, scope: Scope | None = None) -> Encoded:
    """Prüft ``raw`` für den Platzhaltertyp ``ptype`` im Kontext ``sh`` (POSIX-Shell, bash, zsh).

    Gibt den Text für den Befehl zurück oder den ersten Grund, warum der Wert nicht in einen Befehl
    darf. Unbekannte Typen sind ein Programmfehler (``ValueError``)."""
    if ptype not in PLACEHOLDER_TYPES:
        raise ValueError(f"unbekannter Platzhaltertyp {ptype!r}")
    sc = scope or Scope()
    if ptype == "port" and isinstance(raw, int):
        return _enc_port(raw)
    if not isinstance(raw, str) or raw == "":
        return _bad("invalid")
    problem = first_problem(raw, spaces=ptype == "words")
    if problem is not None:
        if problem == "shell_meta" and ptype == "share" and raw.endswith("$") and "$" not in raw[:-1]:
            problem = first_problem(raw[:-1])  # ``C$``: Dollar nur am Ende
        if problem is not None:
            return _bad(problem)
    if ptype == "port":
        return _enc_port(raw)
    if ptype == "ip":
        return _enc_ip(raw, sc)
    if ptype == "cidr":
        return _enc_cidr(raw, sc)
    if ptype == "hostname":
        return _enc_hostname(raw, sc)
    if ptype == "url":
        return _enc_url(raw, sc)
    if ptype == "word":
        return _enc_word(raw)
    if ptype == "words":
        return _enc_words(raw)
    if ptype == "path":
        return _enc_path(raw)
    if ptype == "user":
        return _enc_user(raw)
    return _enc_share(raw)
