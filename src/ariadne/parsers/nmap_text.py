"""Parser ``nmap.text``: nmap-Normalausgabe im Terminal (Befehl ``nmap``) und in ``.nmap``-Dateien.

Erkennt «Nmap scan report for», «Host is up», die Tabelle PORT/STATE/SERVICE/
VERSION, «MAC Address:», «Service Info:», «OS details:», «rDNS record for» und
NSE-Blöcke (``| name: ...``). ``ssh-hostkey``, ``smb-os-discovery``,
``ssl-cert`` und ``nbstat`` werden wie im XML-Parser ausgewertet, damit sich
Claims beider Parser zusammenführen lassen (gleiche Prädikate, gleiche
Normalisierung). Produkt und Version trennt die erste Ziffern-Zeichenfolge,
eine abschliessende Klammer ist ``extrainfo``.

Zieldaten können eigene Zeilen erzeugen. Deshalb zählen nur Zeilen, deren
Anfang exakt einem nmap-Format entspricht; Skriptausgaben beginnen immer mit
``|`` und werden nie als Hostzeilen gelesen.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import ClassVar

from ariadne.parsers._common import (
    canon_ip,
    clip_value,
    nbstat_name,
    nmap_outputs,
    suspect_attrs,
    text_lines,
    tool_argv,
    valid_hostname,
)
from ariadne.parsers.api import Mention, Obs, Ref, Span, Trust, UnitView
from ariadne.parsers.nmap_xml import MAX_SCRIPT_OUTPUT
from ariadne.parsers.safe import rx

__all__ = ["NmapTextParser", "split_version"]

_ROW = (r"^([0-9]{1,5})/(tcp|udp|sctp)\s+"
        r"(open\|filtered|closed\|filtered|unfiltered|filtered|open|closed)\s+(\S+)")
_TEXT_KEYTYPES = {"DSA": "dsa", "RSA": "rsa", "ECDSA": "ecdsa", "ED25519": "ed25519", "RSA1": "rsa1"}


def split_version(text: str) -> tuple[str | None, str | None, str | None]:
    """``"Apache httpd 2.2.8 ((Ubuntu) DAV/2)"`` -> Produkt, Version, Extrainfo."""
    t = text.strip()
    extra: str | None = None
    if t.endswith(")"):
        depth = 0
        for k in range(len(t) - 1, -1, -1):
            if t[k] == ")":
                depth += 1
            elif t[k] == "(":
                depth -= 1
                if depth == 0:
                    extra = t[k + 1 : -1].strip() or None
                    t = t[:k].strip()
                    break
    tokens = [x for x in t.split(" ") if x]
    idx = next((i for i, tok in enumerate(tokens) if tok[0].isdigit()), len(tokens))
    product = " ".join(tokens[:idx]) or None
    version = " ".join(tokens[idx:]) or None
    return product, version, extra


@dataclass
class _Script:
    sid: str
    start: int
    subject: Ref
    svc: Ref | None
    lines: list[str] = field(default_factory=list)
    end: int = 0
    attrs: dict[str, str] = field(default_factory=dict)


class NmapTextParser:
    id: ClassVar[str] = "nmap.text"
    version: ClassVar[str] = "1"
    trust: ClassVar[Trust] = "tool_text"
    auto_eligible: ClassVar[bool] = True

    def match(self, unit: UnitView) -> int:
        if unit.kind == "command":
            return 60 if tool_argv(unit.argv)[0] == "nmap" else 0
        if unit.kind == "file":
            path = (unit.path or "").lower()
            sniff = (unit.sniff or "").lower()
            if path.endswith(".nmap") or sniff in ("nmap.text", "nmap.normal", "nmap-normal"):
                return 60
        if unit.kind in ("file", "segment"):
            for _, _, text in _head(unit, 200):
                if text.startswith(("Starting Nmap ", "Nmap scan report for ", "# Nmap ")):
                    return 40
        return 0

    def companions(self, argv: Sequence[str], cwd: str) -> list[str]:
        outs = nmap_outputs(argv, cwd)
        # .gnmap wird nicht geparst, aber mit dem Befehl verknüpft (Provenienz)
        return list(outs["normal"]) + list(outs["grepable"])

    # ------------------------------------------------------------------ parse
    def parse(self, unit: UnitView) -> Iterator[Obs | Mention]:
        row_rx = rx(_ROW)
        host: Ref | None = None
        svc: Ref | None = None
        ver_col: int | None = None
        has_version = False
        in_table = False
        host_scripts = False
        script: _Script | None = None

        for i, line, text in text_lines(unit):
            sus = suspect_attrs(line)
            if script is not None:
                if text.startswith("|") and len(text) >= 2 and text[1] in " _":
                    new_sid = _script_id(text)
                    if new_sid is None:
                        script.lines.append(text[2:])
                        script.end = i
                        continue
                    yield from self._finish(script)
                    script = None
                else:
                    yield from self._finish(script)
                    script = None
            if text.startswith("|") and len(text) >= 2 and text[1] in " _" and host is not None:
                sid = _script_id(text)
                target = svc if (svc is not None and not host_scripts) else None
                if sid is not None and (target is not None or host_scripts):
                    rest = text[2 + len(sid) + 1 :].strip()
                    script = _Script(sid, i, host, target, [rest] if rest else [], i, sus)
                continue

            if text.startswith("Nmap scan report for "):
                host, svc, in_table, host_scripts = None, None, False, False
                rep = _report(text)
                if rep is None:
                    continue
                ip, name, down = rep
                if down:
                    yield Mention("ip", ip, Span(i, i), {"state": "down", "source": "nmap.text", **sus})
                    continue
                host = Ref.ip(ip)
                yield Obs(host, "host.address", ip, Span(i, i), attrs=sus)
                if name:
                    yield Obs(host, "host.name", name, Span(i, i), attrs={"type": "report", **sus})
                continue
            if host is None:
                continue

            if text.startswith("Host is up"):
                yield Obs(host, "host.state", "up", Span(i, i), attrs=sus)
                continue
            if text.startswith("PORT ") and "STATE" in text and "SERVICE" in text:
                in_table = True
                host_scripts = False
                svc = None
                has_version = "VERSION" in text
                ver_col = text.find("VERSION") if has_version else None
                continue
            m = row_rx.search(text) if in_table else None
            if m is not None:
                port = int(m.group(1))
                if port > 65535:
                    continue
                svc = Ref.service(host, m.group(2), port)
                yield from self._row(svc, text, m, i, sus, has_version, ver_col)
                continue
            if text.startswith("MAC Address: "):
                in_table, svc = False, None
                yield from self._mac(host, text, i, sus)
                continue
            if text.startswith("OS details: "):
                val = clip_value(text[len("OS details: ") :], 256)
                if val:
                    yield Obs(host, "host.os", val, Span(i, i), attrs=sus)
                continue
            if text.startswith("Service Info: "):
                in_table, svc = False, None
                yield from self._service_info(host, text, i, sus)
                continue
            if text.startswith("Host script results:"):
                in_table, svc, host_scripts = False, None, True
                continue
            if text.startswith("rDNS record for "):
                name = valid_hostname(text.split(":", 1)[1] if ":" in text else "")
                if name:
                    yield Obs(host, "host.name", name, Span(i, i), attrs={"type": "PTR", **sus})
                continue
            if not text.strip():
                in_table, svc = False, None
                continue
        if script is not None:
            yield from self._finish(script)

    # ---------------------------------------------------------------- Zeilen
    def _row(self, svc: Ref, text: str, m: object, i: int, sus: dict[str, str], has_version: bool,
             ver_col: int | None) -> Iterator[Obs]:
        state = m.group(3)  # type: ignore[attr-defined]
        raw_name = m.group(4)  # type: ignore[attr-defined]
        span = Span(i, i)
        yield Obs(svc, "service.state", state, span, attrs=sus)
        name = raw_name
        uncertain = name.endswith("?")
        name = name.rstrip("?")
        tunnel = None
        if "/" in name:
            tunnel, name = name.split("/", 1)
        conf = 0.3 if (uncertain or not has_version) else None
        if name and len(name) <= 64:
            yield Obs(svc, "service.name", name, span, confidence=conf, attrs=sus)
        if tunnel in ("ssl", "tls"):
            yield Obs(svc, "service.tunnel", "ssl", span, confidence=conf, attrs=sus)
        if not has_version or ver_col is None:
            return
        svc_end = m.end(4)  # type: ignore[attr-defined]
        if svc_end < ver_col and text[ver_col - 1 : ver_col] == " ":
            vtext = text[ver_col:].strip()  # Spalte wie im Kopf ausgerichtet
        else:
            vtext = text[svc_end:].strip()  # verschobene Spalten: Rest nach dem Dienst
        if not vtext:
            return
        product, version, extra = split_version(vtext)
        for pred, val in (("service.product", product), ("service.version", version),
                          ("service.extrainfo", extra)):
            if val:
                yield Obs(svc, pred, clip_value(val, 256), span, confidence=conf, attrs=sus)

    def _mac(self, host: Ref, text: str, i: int, sus: dict[str, str]) -> Iterator[Obs]:
        rest = text[len("MAC Address: ") :].strip()
        mac_raw, _, vendor = rest.partition(" ")
        mac = mac_raw.lower().replace("-", ":")
        parts = mac.split(":")
        if len(parts) != 6 or any(len(p) != 2 or any(c not in "0123456789abcdef" for c in p)
                                  for p in parts):
            return
        attrs = dict(sus)
        vendor = vendor.strip()
        if vendor.startswith("(") and vendor.endswith(")") and len(vendor) > 2:
            attrs["vendor"] = clip_value(vendor[1:-1], 128)
        yield Obs(host, "host.mac", mac, Span(i, i), attrs=attrs)

    def _service_info(self, host: Ref, text: str, i: int, sus: dict[str, str]) -> Iterator[Obs]:
        for part in text[len("Service Info: ") :].split(";"):
            key, _, val = part.strip().partition(":")
            if key.strip() not in ("Host", "Hosts"):
                continue
            for raw in val.split(","):
                name = valid_hostname(raw)
                if name:
                    yield Obs(host, "host.name", name, Span(i, i),
                              attrs={"type": "service_info", **sus})

    # ---------------------------------------------------------------- Skripte
    def _finish(self, s: _Script) -> Iterator[Obs]:
        span = Span(s.start, max(s.start, s.end))
        body = "\n".join(s.lines).strip()
        attrs = dict(s.attrs)
        if body:
            attrs["output"] = clip_value(body, MAX_SCRIPT_OUTPUT)
        if s.svc is not None:
            yield Obs(s.svc, "service.script", s.sid, span, attrs=attrs)
        else:
            yield Obs(s.subject, "host.script", s.sid, span, attrs=attrs)
        sus = s.attrs
        if s.sid == "ssh-hostkey":
            for ln in s.lines:
                parts = ln.split()
                if len(parts) != 3 or not parts[0].isdigit():
                    continue
                ktype = _TEXT_KEYTYPES.get(parts[2].strip("()").upper())
                fp = parts[1].lower()
                if not ktype or len(fp) != 47 or fp.count(":") != 15:
                    continue
                attrs = {"bits": parts[0], "md5": fp, **sus}
                if s.svc is not None:
                    attrs["service"] = s.svc.key
                    yield Obs(s.svc, "service.ssh_hostkey", f"{ktype} MD5:{fp}", span, attrs=attrs)
                yield Obs(s.subject, "host.sshkey", Ref.sshkey(ktype, f"MD5:{fp}"), span, attrs=attrs)
        elif s.sid == "smb-os-discovery":
            yield from _smb_text(s, span)
        elif s.sid == "ssl-cert" and s.svc is not None:
            names: set[str] = set()
            for ln in s.lines:
                ln = ln.strip()
                if ln.startswith("Subject: "):
                    cn = _cn(ln[len("Subject: ") :])
                    if cn:
                        names.add(cn)
                elif ln.startswith("Subject Alternative Name:"):
                    for part in ln.split(":", 1)[1].split(","):
                        part = part.strip()
                        if part.startswith("DNS:") and part[4:].strip():
                            names.add(clip_value(part[4:], 253).lower())
            for name in sorted(names):
                yield Obs(s.svc, "service.tls_cn", name, span, attrs=dict(sus))
        elif s.sid == "nbstat":
            nb = nbstat_name(body)
            if nb:
                yield Obs(s.subject, "host.netbios", nb, span, attrs=dict(sus))


def _smb_text(s: _Script, span: Span) -> Iterator[Obs]:
    fields: dict[str, str] = {}
    for ln in s.lines:
        key, sep, val = ln.strip().partition(":")
        if sep:
            fields[key.strip()] = val.replace("\\x00", "").replace("\x00", "").strip()
    sus = s.attrs
    host = s.subject
    if fields.get("OS"):
        yield Obs(host, "host.smb_os", clip_value(fields["OS"], 256), span, attrs=dict(sus))
    nb = fields.get("NetBIOS computer name", "")
    if nb and " " not in nb and len(nb) <= 32:
        yield Obs(host, "host.netbios", nb.upper(), span, attrs=dict(sus))
    fqdn = valid_hostname(fields.get("FQDN"))
    if fqdn:
        yield Obs(host, "host.name", fqdn, span, attrs={"type": "smb", **sus})
    if fields.get("Domain name"):
        yield Obs(host, "host.domain", clip_value(fields["Domain name"].lower(), 253), span,
                  attrs=dict(sus))
    wg = fields.get("NetBIOS domain name") or fields.get("Workgroup")
    if wg:
        yield Obs(host, "host.smb_domain", clip_value(wg.upper(), 64), span, attrs=dict(sus))


def _cn(subject: str) -> str | None:
    """commonName aus ``commonName=x/organizationName=y`` (Werte dürfen ``/`` enthalten)."""
    key = "commonName="
    j = subject.find(key)
    if j < 0:
        return None
    rest = subject[j + len(key) :]
    end = len(rest)
    k = rest.find("/")
    while k >= 0:
        nxt = rest[k + 1 :].split("=", 1)[0]
        if "=" in rest[k + 1 :] and nxt.isalpha():
            end = k
            break
        k = rest.find("/", k + 1)
    cn = rest[:end].strip()
    return clip_value(cn, 253).lower() if cn else None


def _script_id(text: str) -> str | None:
    """``| ssh-hostkey: ...`` bzw. ``|_http-title: ...`` -> Skript-ID, sonst None (Fortsetzung)."""
    rest = text[2:]
    if not rest or rest[0] == " ":
        return None
    k = rest.find(":")
    if k <= 0 or k > 64:
        return None
    sid = rest[:k]
    if not all(c.isalnum() or c in "-_." for c in sid) or not sid[0].isalnum():
        return None
    return sid


def _report(text: str) -> tuple[str, str | None, bool] | None:
    """«Nmap scan report for [name (]ip[)] [[host down]]» -> (IP, Name, down)."""
    rest = text[len("Nmap scan report for ") :].strip()
    down = False
    if rest.endswith("]") and "[host down" in rest:
        down = True
        rest = rest[: rest.rfind("[")].strip()
    name: str | None = None
    ip = canon_ip(rest)
    if ip is None and rest.endswith(")") and "(" in rest:
        k = rest.rfind("(")
        ip = canon_ip(rest[k + 1 : -1])
        name = valid_hostname(rest[:k])
    if ip is None:
        return None
    return ip, name, down


def _head(unit: UnitView, n: int) -> Iterator[tuple[int, object, str]]:
    for k, item in enumerate(text_lines(unit)):
        if k >= n:
            return
        yield item
