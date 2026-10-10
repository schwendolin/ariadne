"""Parser ``regex.net``: Regex-Netz über alle Text-Einheiten (Architektur 5.6).

Liefert nur Mentions, nie Beobachtungen. Ob ein Wert Kandidat wird,
entscheidet die Projektion (z. B. IP im Scope).

Erkannt werden IPv4 (validiert, nicht als Teil längerer Punktfolgen, nicht
nach «version», «/» eines Produkts oder mit führenden Nullen), IPv6 (über
``ipaddress``), CIDR, URL (http/https; ein Passwort in der Userinfo wird
maskiert), E-Mail, CVE, ``$krb5asrep$``, ``$krb5tgs$``, NetNTLMv2, crypt
(``$1$ $5$ $6$ $y$``), 32 Hex-Zeichen («hash32»), Private-Key-Blöcke, JWT und
AWS-Schlüssel. Nur re2; Zeilen über 16 KiB werden gekürzt gescannt.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterator, Sequence
from typing import ClassVar
from urllib.parse import urlsplit

from ariadne.parsers._common import suspect_attrs, text_lines
from ariadne.parsers.api import Mention, Span, Trust, UnitView
from ariadne.parsers.safe import rx

__all__ = ["RegexNetParser", "SECRET_TYPES"]

SECRET_TYPES = frozenset(
    {"krb5asrep", "krb5tgs", "netntlmv2", "crypt", "hash32", "privkey", "jwt", "awskey"}
)

_IPV4 = r"[0-9]+(?:\.[0-9]+){3,}"
_IPV6 = r"[0-9A-Fa-f]*:[0-9A-Fa-f]*:[0-9A-Fa-f:.]*"
_URL = r"(?i)https?://[^\s\"'<>`]+"
_EMAIL = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}"
_CVE = r"(?i)cve-[0-9]{4}-[0-9]{4,7}"
_SECRETS: tuple[tuple[str, str, dict[str, str]], ...] = (
    ("krb5asrep", r"\$krb5asrep\$[0-9]{1,2}\$[^\s]{16,}", {}),
    ("krb5tgs", r"\$krb5tgs\$[0-9]{1,2}\$[^\s]{16,}", {}),
    ("netntlmv2", r"[A-Za-z0-9._@$-]{1,64}::[A-Za-z0-9._-]{0,64}:[0-9A-Fa-f]{16}:[0-9A-Fa-f]{32}"
                  r":[0-9A-Fa-f]{20,}", {}),
    ("crypt", r"\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}", {"scheme": "md5crypt"}),
    ("crypt", r"\$5\$(?:rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}",
     {"scheme": "sha256crypt"}),
    ("crypt", r"\$6\$(?:rounds=[0-9]{1,9}\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}",
     {"scheme": "sha512crypt"}),
    ("crypt", r"\$y\$[./0-9A-Za-z]{1,32}\$[./0-9A-Za-z]{1,86}\$[./0-9A-Za-z]{43}", {"scheme": "yescrypt"}),
    ("jwt", r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*", {}),
    ("awskey", r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}", {"part": "id"}),
)
_AWS_KEY_ASSIGN = r"(?i)aws_secret_access_key\s*[=:]\s*[\"']?([A-Za-z0-9/+]{40})"
_HEX32 = r"[0-9A-Fa-f]{32,}"
_PRIVKEY_BEGIN = r"-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----"
_VERSION_WORDS = ("version", "ver", "v", "build", "release", "rev")

_ALNUM = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
_WORD = _ALNUM | {"_"}
_HEXCH = frozenset("0123456789abcdefABCDEF")
_B64URL = _ALNUM | {"_", "-"}
_CRYPT = _ALNUM | {".", "/"}
_COLON_DOT = frozenset(":.")
_MAIL_PREV = frozenset(".%+-")
_NTLM_PREV = frozenset(".@$-")


def _before(text: str, i: int) -> str:
    return text[i - 1] if i > 0 else ""


def _after(text: str, j: int) -> str:
    return text[j] if j < len(text) else ""


class RegexNetParser:
    id: ClassVar[str] = "regex.net"
    version: ClassVar[str] = "1"
    trust: ClassVar[Trust] = "heuristic"
    auto_eligible: ClassVar[bool] = False

    def match(self, unit: UnitView) -> int:
        return 1 if unit.kind in ("command", "segment", "file") and len(unit.lines) > 0 else 0

    def companions(self, argv: Sequence[str], cwd: str) -> list[str]:
        return []

    def parse(self, unit: UnitView) -> Iterator[Mention]:
        lines = list(text_lines(unit))
        skip_until = -1
        for pos, (i, line, text) in enumerate(lines):
            if i <= skip_until:
                continue
            sus = suspect_attrs(line)
            if "PRIVATE KEY-----" in text:
                block = self._privkey(lines, pos, sus)
                if block is not None:
                    mention, last = block
                    skip_until = last
                    yield mention
                    continue
            found: list[tuple[int, int, Mention]] = []
            covered: list[tuple[int, int]] = []
            self._secrets(text, i, sus, found, covered)
            urls = self._urls(text, i, sus, found)
            v6 = self._ipv6(text, i, sus, found, urls)
            self._ipv4(text, i, sus, found, urls, v6)
            self._emails(text, i, sus, found, urls)
            self._cves(text, i, sus, found)
            self._hash32(text, i, sus, found, covered)
            found.sort(key=lambda t: (t[0], t[1], t[2].value_type))
            for a, b, m in found:
                # Werte innerhalb eines Secrets (z. B. user@realm im AS-REP-Hash) nicht doppelt melden
                if m.value_type not in SECRET_TYPES and any(ca <= a and b <= cb for ca, cb in covered):
                    continue
                yield m

    # ------------------------------------------------------------ Netzwerk
    def _ipv4(self, text: str, i: int, sus: dict[str, str], out: list, urls: list[tuple[int, int]],
              v6: list[tuple[int, int]]) -> None:
        if "." not in text:
            return
        for m in rx(_IPV4).finditer(text):
            a, b = m.span()
            if any(va <= a and b <= vb for va, vb in v6):
                continue  # schon als IPv4-mapped IPv6 erkannt
            parts = m.group(0).split(".")
            if len(parts) != 4 or any(len(p) > 3 or (len(p) > 1 and p[0] == "0") or int(p) > 255
                                      for p in parts):
                continue
            if parts[0] == "0":
                continue
            prev, nxt = _before(text, a), _after(text, b)
            if prev in _WORD or prev == ".":
                continue
            if prev == "/" and a >= 2 and text[a - 2] in _ALNUM:
                continue  # Produkt/Version wie Apache/2.4.41.1
            if nxt in _WORD:
                continue
            if nxt == "." and _after(text, b + 1) in _ALNUM:
                continue  # Teil eines längeren Namens
            if self._after_version_word(text, a):
                continue
            ip = m.group(0)
            attrs = {"family": "4", **sus}
            if any(ua <= a and b <= ub for ua, ub in urls):
                attrs["in_url"] = "1"
            if nxt == "/":
                cidr = self._prefix(text, b + 1, 32)
                if cidr is not None:
                    plen, end = cidr
                    net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
                    out.append((a, end, Mention("cidr", str(net), Span(i, i, a, end),
                                                {"family": "4", "written": f"{ip}/{plen}", **sus})))
                    if str(net.network_address) == ip and plen < 32:
                        continue  # Netzadresse: nur CIDR
            out.append((a, b, Mention("ip", ip, Span(i, i, a, b), attrs)))

    @staticmethod
    def _prefix(text: str, k: int, maxlen: int) -> tuple[int, int] | None:
        j = k
        while j < len(text) and j - k < 3 and text[j].isdigit():
            j += 1
        if j == k or (j < len(text) and (text[j] in _WORD or text[j] == ".")):
            return None
        val = int(text[k:j])
        return (val, j) if val <= maxlen else None

    @staticmethod
    def _after_version_word(text: str, a: int) -> bool:
        k = a
        while k > 0 and text[k - 1] in " :=":
            k -= 1
        j = k
        while j > 0 and text[j - 1].isalpha():
            j -= 1
        return k < a and text[j:k].lower() in _VERSION_WORDS

    def _ipv6(self, text: str, i: int, sus: dict[str, str], out: list, urls: list[tuple[int, int]]
              ) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        if text.count(":") < 2:
            return spans
        for m in rx(_IPV6).finditer(text):
            a, b = m.span()
            cand = m.group(0)
            if _before(text, a) in _WORD or _before(text, a) in _COLON_DOT:
                continue
            while cand and cand[-1] in ".:" and not cand.endswith("::"):
                cand = cand[:-1]
            b = a + len(cand)
            if _after(text, b) in _WORD or cand in ("::",) or "::" not in cand and cand.count(":") != 7:
                continue
            try:
                addr = ipaddress.IPv6Address(cand)
            except ValueError:
                continue
            attrs = {"family": "6", **sus}
            if any(ua <= a and b <= ub for ua, ub in urls):
                attrs["in_url"] = "1"
            if _after(text, b) == "/":
                pre = self._prefix(text, b + 1, 128)
                if pre is not None:
                    plen, end = pre
                    net = ipaddress.ip_network(f"{addr}/{plen}", strict=False)
                    out.append((a, end, Mention("cidr", str(net), Span(i, i, a, end),
                                                {"family": "6", "written": f"{cand}/{plen}", **sus})))
                    if net.network_address == addr and plen < 128:
                        continue
            mapped = addr.ipv4_mapped
            if mapped is not None:
                attrs["family"] = "4"
                attrs["written"] = cand
            value = str(mapped) if mapped is not None else str(addr)
            spans.append((a, b))
            out.append((a, b, Mention("ip", value, Span(i, i, a, b), attrs)))
        return spans

    def _urls(self, text: str, i: int, sus: dict[str, str], out: list) -> list[tuple[int, int]]:
        spans: list[tuple[int, int]] = []
        if "://" not in text:
            return spans
        for m in rx(_URL).finditer(text):
            a = m.start()
            if _before(text, a) in _WORD:
                continue
            url = m.group(0)
            while url and url[-1] in ".,;:!?'\"]}>":
                url = url[:-1]
            if url.endswith(")") and url.count("(") < url.count(")"):
                url = url[:-1]
            b = a + len(url)
            try:
                parts = urlsplit(url)
                _ = parts.port
            except ValueError:
                continue
            if not parts.hostname:
                continue
            attrs = dict(sus)
            if parts.password is not None:
                netloc = parts.netloc
                userinfo, _, hostport = netloc.rpartition("@")
                user = userinfo.split(":", 1)[0]
                url = url.replace(netloc, f"{user}:***@{hostport}", 1)
                attrs["userinfo"] = "masked"
            spans.append((a, b))
            out.append((a, b, Mention("url", url, Span(i, i, a, b), attrs)))
        return spans

    def _emails(self, text: str, i: int, sus: dict[str, str], out: list, urls: list[tuple[int, int]]
                ) -> None:
        if "@" not in text:
            return
        for m in rx(_EMAIL).finditer(text):
            a, b = m.span()
            if _before(text, a) in _WORD or _before(text, a) in _MAIL_PREV:
                continue
            if any(ua <= a and b <= ub for ua, ub in urls):
                continue
            val = m.group(0).rstrip(".")
            b = a + len(val)
            if _after(text, b) in _WORD:
                continue
            out.append((a, b, Mention("email", val.lower(), Span(i, i, a, b), dict(sus))))

    def _cves(self, text: str, i: int, sus: dict[str, str], out: list) -> None:
        if "cve" not in text.lower():
            return
        for m in rx(_CVE).finditer(text):
            a, b = m.span()
            if _before(text, a) in _ALNUM or _after(text, b) in _ALNUM:
                continue
            out.append((a, b, Mention("cve", m.group(0).upper(), Span(i, i, a, b), dict(sus))))

    # ------------------------------------------------------------- Secrets
    def _secrets(self, text: str, i: int, sus: dict[str, str], out: list,
                 covered: list[tuple[int, int]]) -> None:
        has_dollar = "$" in text
        for vtype, pattern, extra in _SECRETS:
            if vtype in ("krb5asrep", "krb5tgs", "crypt") and not has_dollar:
                continue
            if vtype == "netntlmv2" and "::" not in text:
                continue
            if vtype == "jwt" and "eyJ" not in text:
                continue
            if vtype == "awskey" and not any(p in text for p in ("AKIA", "ASIA", "AGPA", "AIDA", "AROA",
                                                                 "ANPA", "ANVA", "AIPA")):
                continue
            for m in rx(pattern).finditer(text):
                a, b = m.span()
                if any(ca <= a < cb for ca, cb in covered):
                    continue
                prev, nxt = _before(text, a), _after(text, b)
                if vtype == "netntlmv2" and (prev in _WORD or prev in _NTLM_PREV):
                    continue
                if vtype == "crypt" and (nxt in _CRYPT or prev in _CRYPT):
                    continue
                if vtype == "jwt" and (prev in _B64URL or nxt in _B64URL):
                    continue
                if vtype == "awskey" and (prev in _ALNUM or nxt in _ALNUM):
                    continue
                covered.append((a, b))
                out.append((a, b, Mention(vtype, m.group(0), Span(i, i, a, b), {**extra, **sus})))
        if "aws_secret_access_key" in text.lower():
            for m in rx(_AWS_KEY_ASSIGN).finditer(text):
                a, b = m.span(1)
                covered.append((a, b))
                out.append((a, b, Mention("awskey", m.group(1), Span(i, i, a, b), {"part": "secret", **sus})))

    def _hash32(self, text: str, i: int, sus: dict[str, str], out: list,
                covered: list[tuple[int, int]]) -> None:
        for m in rx(_HEX32).finditer(text):
            a, b = m.span()
            if b - a != 32:
                continue
            if _before(text, a) in _WORD or _after(text, b) in _WORD:
                continue
            if any(ca <= a < cb for ca, cb in covered):
                continue
            val = m.group(0)
            if not any(c.isdigit() for c in val):
                continue
            out.append((a, b, Mention("hash32", val.lower(), Span(i, i, a, b), dict(sus))))

    def _privkey(self, lines: list, pos: int, sus: dict[str, str]) -> tuple[Mention, int] | None:
        i, _, text = lines[pos]
        m = rx(_PRIVKEY_BEGIN).search(text)
        if m is None:
            return None
        kind = (m.group(1) or "").strip() or "PKCS8"
        body = [text[m.start():]]
        last = i
        complete = False
        for j in range(pos + 1, min(len(lines), pos + 400)):
            k, _, t = lines[j]
            body.append(t)
            last = k
            if "-----END " in t and "PRIVATE KEY-----" in t:
                end = t.find("PRIVATE KEY-----") + len("PRIVATE KEY-----")
                body[-1] = t[:end]
                complete = True
                break
        if not complete:
            body = body[:1]
            last = i
        value = "\n".join(s.strip() for s in body)
        attrs = {"kind": kind, "complete": "1" if complete else "0", **sus}
        return Mention("privkey", value, Span(i, last), attrs), last
