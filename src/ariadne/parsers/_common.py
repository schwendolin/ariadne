"""Gemeinsame Helfer der eingebauten Parser. Nur re2, kein Standard-``re``."""

from __future__ import annotations

import ipaddress
import posixpath
from collections.abc import Iterator, Sequence

from ariadne.ctxrules import strip_prefixes
from ariadne.parsers.api import Line, UnitView
from ariadne.parsers.safe import clip

__all__ = [
    "tool_argv",
    "text_lines",
    "suspect_attrs",
    "unit_bytes",
    "canon_ip",
    "valid_hostname",
    "clip_value",
    "nmap_outputs",
    "join_cwd",
    "nbstat_name",
]

MAX_VALUE = 1024


def tool_argv(argv: Sequence[str]) -> tuple[str, list[str]]:
    """Name des Tools (ohne Pfad und Wrapper wie sudo) und die restlichen Argumente."""
    args = strip_prefixes(list(argv))
    if not args:
        return "", []
    return posixpath.basename(args[0]), list(args[1:])


def text_lines(unit: UnitView) -> Iterator[tuple[int, Line, str]]:
    """Zeilen ohne Prompt-Echo, mit Index und auf 16 KiB gekürztem Text."""
    for i, line in enumerate(unit.lines):
        if line.prompt_echo:
            continue
        yield i, line, clip(line.text)


def suspect_attrs(line: Line) -> dict[str, str]:
    """Verdeckter oder überschriebener Text erzeugt einen Injection-Verdacht."""
    if line.concealed:
        return {"suspect": "concealed"}
    if line.overwritten:
        return {"suspect": "overwritten"}
    return {}


def unit_bytes(unit: UnitView) -> bytes:
    """Bytes einer Datei-Einheit; bei Befehlen die Zeilen, mit LF verbunden."""
    if unit.kind == "file":
        try:
            data = unit.open_bytes()
        except Exception:  # Blob fehlt: dann aus den Zeilen
            data = b""
        if data:
            return data
    # Prompt-Echo bleibt als Leerzeile stehen, damit Zeilennummern stimmen
    return "\n".join("" if line.prompt_echo else line.text for line in unit.lines).encode()


def canon_ip(text: str) -> str | None:
    """Kanonische IP-Adresse (IPv4-mapped wird IPv4) oder None."""
    s = text.strip()
    if not s or len(s) > 64:
        return None
    if "%" in s:
        s = s.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_")


def valid_hostname(name: str | None) -> str | None:
    """Hostname in Kleinschreibung, ohne Punkt am Ende, nur ASCII-Labels; sonst None."""
    if not name:
        return None
    s = name.strip().lower().rstrip(".")
    if not s or len(s) > 253 or canon_ip(s) is not None:
        return None
    for label in s.split("."):
        if not label or len(label) > 63 or any(c not in _HOST_CHARS for c in label):
            return None
        if label[0] == "-" or label[-1] == "-":
            return None
    return s


def clip_value(text: str, limit: int = MAX_VALUE) -> str:
    """Begrenzt einen Wert aus Zieldaten (Länge, Steuerzeichen bleiben Sache der Senken)."""
    s = text.strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def join_cwd(path: str, cwd: str | None) -> str:
    """Pfad relativ zu cwd auflösen; absolute Pfade und ``~`` bleiben (keine Umgebung im Worker)."""
    if path.startswith(("/", "~")) or not cwd:
        return posixpath.normpath(path) if path.startswith("/") else path
    return posixpath.normpath(posixpath.join(cwd, path))


_NMAP_OUT = {"-oX": "xml", "-oN": "normal", "-oG": "grepable", "-oS": "normal", "-oA": "all"}


def nmap_outputs(argv: Sequence[str], cwd: str | None) -> dict[str, list[str]]:
    """Ausgabedateien eines nmap-Aufrufs: ``{"xml": [...], "normal": [...], "grepable": [...]}``.

    ``-oX F``, ``--oX F``, ``-oX=F``; ``-oA B`` ergibt ``B.xml``, ``B.nmap``,
    ``B.gnmap``. ``-`` (stdout) ist keine Datei und steht unter ``"stdout"``.
    """
    out: dict[str, list[str]] = {"xml": [], "normal": [], "grepable": [], "stdout": []}
    tool, rest = tool_argv(argv)
    if tool != "nmap":
        return out
    i = 0
    while i < len(rest):
        arg = rest[i]
        opt, val = arg, None
        if arg.startswith("--o"):
            opt = arg[1:]
        if "=" in opt:
            opt, val = opt.split("=", 1)
        kind = _NMAP_OUT.get(opt)
        if kind is None:
            i += 1
            continue
        if val is None:
            if i + 1 >= len(rest):
                break
            val = rest[i + 1]
            i += 2
        else:
            i += 1
        if not val:
            continue
        if val == "-":
            out["stdout"].append(kind)
            continue
        if kind == "all":
            base = join_cwd(val, cwd)
            out["xml"].append(base + ".xml")
            out["normal"].append(base + ".nmap")
            out["grepable"].append(base + ".gnmap")
        else:
            out[kind].append(join_cwd(val, cwd))
    return out


def nbstat_name(output: str) -> str | None:
    """NetBIOS-Name aus der Ausgabe von ``nbstat`` (``NetBIOS name: X, ...``)."""
    key = "NetBIOS name:"
    j = output.find(key)
    if j < 0:
        return None
    name = output[j + len(key) :].split(",", 1)[0].strip()
    name = name.replace("\\x00", "").replace("\x00", "").strip()
    if not name or " " in name or len(name) > 32 or name.startswith("<"):
        return None
    return name.upper()
