"""Normalisierung von Kennungen vor jeder Scope-Prüfung (Architektur 5.8).

Nur Standardbibliothek. Keine DNS-Auflösung, nie.

* Hostnamen: Kleinschreibung, Punkt am Ende weg, IDNA (2003, ``encodings.idna``)
  zu A-Labels. Gemischte Schriften in einem Label (Latein und Kyrillisch)
  ergeben ``None``, also ``unknown``.
* IPv4 auch in den Formen von ``inet_aton`` (``10.1``, ``167772165``, Hex,
  Oktal). Ist eine Schreibweise mehrdeutig (``010.1.1.1``), liefert
  :func:`ipv4_candidates` alle Lesarten; das strengste Urteil gilt.
* IPv6 kanonisch, IPv4-mapped wird zu IPv4.
* URLs streng: nur ``http``/``https``, kein Backslash, keine Userinfo, keine
  Steuer- oder Leerzeichen, kein ``%`` im Host.

Kennungen haben die Form ``ip:default/<adresse>``, ``fqdn:<name>`` und
``url:<url>`` (siehe ``ariadne.parsers.api.Ref``).
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import quote

__all__ = [
    "SPACE",
    "has_control",
    "normalize_hostname",
    "ipv4_candidates",
    "normalize_ip",
    "normalize_url",
    "split_url",
    "split_host_port",
    "to_identifier",
    "mixed_script",
]

SPACE = "default"  # v0.1 kennt nur einen Adressraum

_LABEL = re.compile(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")
_DEC = re.compile(r"[0-9]+")
_HEX = re.compile(r"[0-9a-fA-F]*")
_OCT = re.compile(r"[0-7]+")
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)://")
_PORT = re.compile(r"[0-9]{1,5}")
_DEFAULT_PORT = {"http": "80", "https": "443"}
# UTS 39 «highly restrictive»: erlaubte Kombinationen mehrerer Schriften
_SCRIPT_SETS = (
    frozenset({"LATIN", "HAN", "HIRAGANA", "KATAKANA"}),
    frozenset({"LATIN", "HAN", "BOPOMOFO"}),
    frozenset({"LATIN", "HAN", "HANGUL"}),
)
_MAX_INPUT = 8192


def has_control(text: str) -> bool:
    """Steuerzeichen, Format-Zeichen (Bidi, Zero-Width) oder Leerzeichen ausser ASCII-Space."""
    for ch in text:
        cp = ord(ch)
        if cp < 0x20 or 0x7F <= cp <= 0x9F:
            return True
        if cp > 0x7F and unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp", "Zs"):
            return True
    return False


def _script(ch: str) -> str | None:
    if not unicodedata.category(ch).startswith("L"):
        return None  # Ziffern, Bindestrich, Zeichen ohne Schrift
    first = unicodedata.name(ch, "UNKNOWN").split(" ", 1)[0]
    return "HAN" if first == "CJK" else first


def mixed_script(label: str) -> bool:
    """True, wenn ein Label Buchstaben aus unzulässig gemischten Schriften enthält."""
    scripts = {s for s in map(_script, label) if s is not None}
    if len(scripts) <= 1:
        return False
    return not any(scripts <= allowed for allowed in _SCRIPT_SETS)


def normalize_hostname(raw: str) -> str | None:
    """Hostname als A-Label-Form in Kleinschreibung oder ``None``.

    Endet der Name auf ein numerisches Label, ist er kein Hostname, sondern
    eine (eventuell ungültige) IPv4-Schreibweise.
    """
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or len(s) > 300 or has_control(s) or " " in s:
        return None
    if s.endswith("."):
        s = s[:-1]
    if not s:
        return None
    try:
        ascii_name = s.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return None
    if len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    for label in labels:
        if not _LABEL.fullmatch(label):
            return None
        if label.startswith("xn--"):
            try:
                ulabel = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                return None
            if mixed_script(ulabel):
                return None
        elif "--" in label[2:4]:
            return None  # reservierte Form ab3--
    if _ends_in_number(labels[-1]):
        return None
    return ascii_name


# --------------------------------------------------------------------------- IP


def _ends_in_number(part: str) -> bool:
    if _DEC.fullmatch(part):
        return True
    return part[:2] in ("0x", "0X") and bool(_HEX.fullmatch(part[2:]))


def _part_value(p: str) -> int | None:
    """Wert eines Teils wie bei ``inet_aton``: 0x.. hex, 0.. oktal, sonst dezimal."""
    if not p or len(p) > 32:
        return None
    if p[:2] in ("0x", "0X"):
        h = p[2:]
        if not _HEX.fullmatch(h):
            return None
        return int(h, 16) if h else 0
    if len(p) > 1 and p[0] == "0":
        return int(p, 8) if _OCT.fullmatch(p) else None
    return int(p) if _DEC.fullmatch(p) else None


def _inet_aton(parts: list[str]) -> int | None:
    if not 1 <= len(parts) <= 4:
        return None
    vals = [_part_value(p) for p in parts]
    if any(v is None for v in vals):
        return None
    nums: list[int] = [v for v in vals if v is not None]
    for v in nums[:-1]:
        if v > 255:
            return None
    rest_bits = 8 * (5 - len(nums))
    if nums[-1] >= 1 << rest_bits:
        return None
    value = 0
    for i, v in enumerate(nums[:-1]):
        value |= v << (24 - 8 * i)
    return value | nums[-1]


def _strict_decimal(parts: list[str]) -> int | None:
    if len(parts) != 4 or not all(_DEC.fullmatch(p) and len(p) <= 3 for p in parts):
        return None
    nums = [int(p) for p in parts]
    if any(n > 255 for n in nums):
        return None
    return (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]


def ipv4_candidates(raw: str) -> list[str | None] | None:
    """Alle Lesarten einer IPv4-artigen Schreibweise.

    ``None``: nicht IPv4-artig (also ein Name). Sonst eine Liste mit der Lesart
    von ``inet_aton`` (``None`` = ungültig, also unbekannt) und, falls
    abweichend, der streng dezimalen Lesart. ``010.1.1.1`` ergibt
    ``["8.1.1.1", "10.1.1.1"]``.
    """
    s = raw.strip()
    if not s or len(s) > 64:
        return None
    parts = s.split(".")
    if len(parts) > 1 and parts[-1] == "":
        parts = parts[:-1]
    if not parts or not _ends_in_number(parts[-1]):
        return None
    a = _inet_aton(parts)
    d = _strict_decimal(parts)
    out: list[str | None] = [str(ipaddress.IPv4Address(a)) if a is not None else None]
    if d is not None and d != a:
        out.append(str(ipaddress.IPv4Address(d)))
    return out


def _ipv6(s: str) -> str | None:
    try:
        addr = ipaddress.IPv6Address(s)
    except ValueError:
        return None
    if addr.scope_id:
        addr = ipaddress.IPv6Address(str(addr).split("%", 1)[0])
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return str(mapped)
    return addr.compressed


def normalize_ip(raw: str) -> str | None:
    """Kanonische IP-Adresse oder ``None`` (auch bei mehrdeutigem IPv4)."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or len(s) > 128 or has_control(s):
        return None
    if s.startswith("[") and s.endswith("]"):
        return _ipv6(s[1:-1])
    if ":" in s:
        return _ipv6(s)
    cands = ipv4_candidates(s)
    if not cands or cands[0] is None or len(cands) > 1:
        return None
    return cands[0]


# --------------------------------------------------------------------------- URL


def split_host_port(authority: str) -> tuple[str, str | None] | None:
    """``host[:port]`` oder ``[v6][:port]`` zerlegen; ``None`` bei Unsinn."""
    if authority.startswith("["):
        end = authority.find("]")
        if end < 0:
            return None
        host, after = authority[: end + 1], authority[end + 1 :]
        if not after:
            return host, None
        if after[0] != ":" or not _PORT.fullmatch(after[1:]):
            return None
        return host, after[1:]
    if authority.count(":") > 1:
        return None
    host, sep, port = authority.partition(":")
    if not sep:
        return host, None
    if not _PORT.fullmatch(port):
        return None
    return host, port


def _url_host(host: str) -> str | None:
    """Host einer URL normalisiert; IPv6 in Klammern, IPv4-mapped als IPv4."""
    if not host or "%" in host:
        return None
    if host.startswith("["):
        v6 = _ipv6(host[1:-1])
        if v6 is None:
            return None
        return v6 if ":" not in v6 else f"[{v6}]"
    cands = ipv4_candidates(host)
    if cands is not None:
        # WHATWG: endet der Host auf eine Zahl, muss er eine gültige IPv4 sein.
        if cands[0] is None or len(cands) > 1:
            return None
        return cands[0]
    return normalize_hostname(host)


def split_url(raw: str) -> tuple[str, str, str | None, str] | None:
    """Strenge Zerlegung in (scheme, host, port, rest) ohne Normalisierung des Hosts."""
    if not isinstance(raw, str):
        return None
    s = raw.strip(" ")
    if not s or len(s) > _MAX_INPUT or has_control(s) or " " in s or "\\" in s:
        return None
    m = _SCHEME.match(s)
    if not m:
        return None
    scheme = m.group(1).lower()
    if scheme not in _DEFAULT_PORT:
        return None
    rest = s[m.end() :]
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if 0 <= i < cut:
            cut = i
    authority, tail = rest[:cut], rest[cut:]
    if not authority or "@" in authority:
        return None
    hp = split_host_port(authority)
    if hp is None:
        return None
    host, port = hp
    if port is not None and int(port) > 65535:
        return None
    return scheme, host, port, tail


def normalize_url(raw: str) -> str | None:
    """URL streng normalisiert (ohne Fragment, ohne Standard-Port) oder ``None``."""
    parts = split_url(raw)
    if parts is None:
        return None
    scheme, host, port, tail = parts
    host_n = _url_host(host)
    if host_n is None:
        return None
    if port is not None:
        port = str(int(port))
        if port == _DEFAULT_PORT[scheme]:
            port = None
    tail = tail.split("#", 1)[0]
    if not tail.startswith("/"):
        tail = "/" + tail
    tail = "".join(c if ord(c) < 0x80 else quote(c, safe="") for c in tail)
    return f"{scheme}://{host_n}{':' + port if port else ''}{tail}"


# --------------------------------------------------------------------------- Kennung


def _from_identifier(s: str) -> str | None:
    kind, _, value = s.partition(":")
    if kind == "ip":
        space, sep, addr = value.partition("/")
        if not sep or space != SPACE:
            return None
        ip = normalize_ip(addr)
        return f"ip:{SPACE}/{ip}" if ip else None
    if kind == "fqdn":
        h = normalize_hostname(value)
        return f"fqdn:{h}" if h else None
    if kind == "url":
        u = normalize_url(value)
        return f"url:{u}" if u else None
    return None


def to_identifier(raw: str) -> str | None:
    """Rohwert (IP, Name, URL) oder Kennung zu einer kanonischen Kennung.

    Ergebnis ``ip:default/..``, ``fqdn:..``, ``url:..`` oder ``None``
    (unbekannt, mehrdeutig oder ungültig). Ports (``host:445``) und CIDR
    gehören nicht zu einer Kennung und ergeben ``None``.
    """
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or len(s) > _MAX_INPUT or has_control(s):
        return None
    if s.startswith(("ip:", "fqdn:", "url:")):
        return _from_identifier(s)
    if "://" in s:
        u = normalize_url(s)
        return f"url:{u}" if u else None
    ip = normalize_ip(s)
    if ip:
        return f"ip:{SPACE}/{ip}"
    if ":" in s or ipv4_candidates(s) is not None:
        return None
    h = normalize_hostname(s)
    return f"fqdn:{h}" if h else None
