"""Parser ``nmap.xml``: nmap-XML-Ausgabe (``-oX``, ``-oA``) in Datei-Einheiten.

Liefert pro Host Status, Adressen, MAC (mit Hersteller), Namen, OS (beste
Übereinstimmung), Ports mit Dienst (``method="table"`` senkt auf 0.3), CPE und
NSE-Skripte (``ssh-hostkey``, ``smb-os-discovery``, ``ssl-cert`` gesondert).

Robustheit: Unvollständiges XML (Abbruch, Datei wächst noch) liefert nur
vollständige ``host``-Elemente, nie einen Absturz. DTD, Entities und externe
Verweise brechen mit :class:`~ariadne.parsers.safe.UnsafeXmlError` ab, ohne
etwas auszuwerten. Hosts mit Status ``down`` werden nur als Mention vermerkt,
damit ein /24-Scan die Karte nicht mit toten Adressen füllt.

Fundstellen: XPath-ähnlicher Pfad (``/nmaprun/host[2]/ports/port[3]``) und
Zeilenbereich, gefunden über die öffnenden Tags in den Zeilen.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Iterator, Sequence
from typing import Any, ClassVar

from ariadne.parsers._common import (
    canon_ip,
    clip_value,
    nbstat_name,
    nmap_outputs,
    unit_bytes,
    valid_hostname,
)
from ariadne.parsers.api import Mention, Obs, Ref, Span, Trust, UnitView
from ariadne.parsers.safe import ParseError, decode, safe_xml_iterparse

__all__ = ["NmapXmlParser", "ssh_key_type", "ssh_fingerprint"]

MAX_SCRIPT_OUTPUT = 2000
_PROTOS = ("tcp", "udp", "sctp")
_KEY_TYPES = {
    "ssh-dss": "dsa",
    "dsa": "dsa",
    "ssh-rsa": "rsa",
    "rsa": "rsa",
    "rsa1": "rsa1",
    "ssh-ed25519": "ed25519",
    "ed25519": "ed25519",
    "ecdsa": "ecdsa",
}


def ssh_key_type(raw: str) -> str | None:
    """Kurzform des Schlüsseltyps: dsa, rsa, ecdsa, ed25519."""
    t = raw.strip().lower()
    if t.startswith("ecdsa"):
        return "ecdsa"
    return _KEY_TYPES.get(t)


def ssh_fingerprint(key_b64: str) -> str | None:
    """OpenSSH-Fingerprint ``SHA256:<base64 ohne Padding>`` aus dem Base64-Schlüssel."""
    try:
        raw = base64.b64decode(key_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not raw:
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _md5_colons(hexstr: str) -> str | None:
    h = hexstr.strip().lower()
    if len(h) != 32 or any(c not in "0123456789abcdef" for c in h):
        return None
    return ":".join(h[i : i + 2] for i in range(0, 32, 2))


def _strip_nul(text: str | None) -> str:
    """nmap schreibt NUL-Bytes in NetBIOS-Namen als ``\\x00``."""
    if not text:
        return ""
    return text.replace("\\x00", "").replace("\x00", "").strip()


class _Locator:
    """Findet Zeilen öffnender Tags, damit Fundstellen Zeilen haben."""

    def __init__(self, text: str) -> None:
        self.lines = text.split("\n")
        self.host_open: list[int] = []
        self.host_close: list[int] = []
        for no, line in enumerate(self.lines):
            start = 0
            while True:
                j = line.find("<host", start)
                if j < 0:
                    break
                nxt = line[j + 5 : j + 6]
                if nxt in ("", " ", "\t", ">", "/", "\r"):
                    self.host_open.append(no)
                start = j + 5
            k = line.find("</host>")
            while k >= 0:
                self.host_close.append(no)
                k = line.find("</host>", k + 7)

    def host_range(self, idx: int) -> tuple[int, int]:
        a = self.host_open[idx - 1] if idx - 1 < len(self.host_open) else 0
        b = self.host_close[idx - 1] if idx - 1 < len(self.host_close) else a
        return a, max(a, b)

    def find(self, a: int, b: int, *needles: str) -> int:
        for no in range(a, min(b, len(self.lines) - 1) + 1):
            line = self.lines[no]
            if all(n in line for n in needles):
                return no
        return a


def _elem_map(node: Any) -> dict[str, str]:
    """``<elem key="k">v</elem>`` direkt unter ``node`` als Dict."""
    out: dict[str, str] = {}
    for e in node.findall("elem"):
        key = e.get("key")
        if key and e.text is not None:
            out[key] = e.text
    return out


class NmapXmlParser:
    id: ClassVar[str] = "nmap.xml"
    version: ClassVar[str] = "1"
    trust: ClassVar[Trust] = "structured"
    auto_eligible: ClassVar[bool] = True

    # ------------------------------------------------------------------ match
    def match(self, unit: UnitView) -> int:
        if unit.kind == "file":
            sniff = (unit.sniff or "").lower()
            if "nmaprun" in sniff or sniff in ("nmap.xml", "nmap-xml", "nmap_xml"):
                return 100
            path = (unit.path or "").lower()
            mime = (unit.mime or "").lower()
            if path.endswith(".xml") or "xml" in mime:
                try:
                    head = unit.open_bytes()[:4096]
                except Exception:  # Blob nicht lesbar: nicht zuständig
                    return 0
                return 90 if b"<nmaprun" in head else 0
            return 0
        if unit.kind == "command":
            outs = nmap_outputs(unit.argv, unit.cwd)
            if "xml" in outs["stdout"] or "all" in outs["stdout"]:
                return 90
        return 0

    def companions(self, argv: Sequence[str], cwd: str) -> list[str]:
        return list(nmap_outputs(argv, cwd)["xml"])

    # ------------------------------------------------------------------ parse
    def parse(self, unit: UnitView) -> Iterator[Obs | Mention]:
        data = unit_bytes(unit)
        if unit.kind == "command":
            j = data.find(b"<?xml")
            if j < 0:
                j = data.find(b"<nmaprun")
            if j < 0:
                return
            # Zeilen vor dem XML (z. B. Warnungen) zählen für die Fundstellen mit
            prefix_lines = data[:j].count(b"\n")
            data = b"\n" * prefix_lines + data[j:]
        loc = _Locator(decode(data))
        root_seen = False
        host_idx = 0
        try:
            for event, elem in safe_xml_iterparse(data, events=("start", "end")):
                if event == "start":
                    if not root_seen:
                        root_seen = True
                        if elem.tag != "nmaprun":
                            return
                    continue
                if elem.tag == "host":
                    host_idx += 1
                    yield from self._host(elem, host_idx, loc)
                    elem.clear()
        except ParseError:
            return  # unvollständig oder kaputt: nur bis hier vollständige Hosts

    # ------------------------------------------------------------------ host
    def _host(self, h: Any, idx: int, loc: _Locator) -> Iterator[Obs | Mention]:
        hpath = f"/nmaprun/host[{idx}]"
        a, b = loc.host_range(idx)
        ips: list[tuple[str, str]] = []  # (Adresse, Originaltext)
        macs: list[tuple[str, str | None, str]] = []
        for ad in h.findall("address"):
            raw = ad.get("addr") or ""
            atype = (ad.get("addrtype") or "").lower()
            if atype in ("ipv4", "ipv6"):
                ip = canon_ip(raw)
                if ip:
                    ips.append((ip, raw))
            elif atype == "mac":
                mac = _mac(raw)
                if mac:
                    macs.append((mac, ad.get("vendor"), raw))
        if not ips:
            return
        ips.sort(key=lambda t: ":" in t[0])  # IPv4 zuerst
        primary = ips[0][0]
        subj = Ref.ip(primary)
        status = h.find("status")
        state = (status.get("state") or "").lower() if status is not None else ""
        sline = loc.find(a, b, "<status")
        if state == "down":
            attrs = {"state": "down", "source": "nmap.xml"}
            if status is not None and status.get("reason"):
                attrs["reason"] = clip_value(status.get("reason") or "", 64)
            yield Mention("ip", primary, Span(sline, sline, path=f"{hpath}/status"), attrs)
            return
        if state == "up":
            reason = status.get("reason") if status is not None else None
            yield Obs(subj, "host.state", "up", Span(sline, sline, path=f"{hpath}/status"),
                      attrs={"reason": clip_value(reason, 64)} if reason else {})
        for n, (ip, raw) in enumerate(ips, 1):
            line = loc.find(a, b, "<address", f'addr="{raw}"')
            yield Obs(subj, "host.address", ip, Span(line, line, path=f"{hpath}/address[{n}]"))
        for mac, vendor, raw in macs:
            line = loc.find(a, b, "<address", f'addr="{raw}"')
            attrs = {"vendor": clip_value(vendor, 128)} if vendor else {}
            yield Obs(subj, "host.mac", mac, Span(line, line, path=f"{hpath}/address[@addrtype='mac']"),
                      attrs=attrs)
        for n, hn in enumerate(h.findall("hostnames/hostname"), 1):
            raw = hn.get("name") or ""
            name = valid_hostname(raw)
            if not name:
                continue
            line = loc.find(a, b, "<hostname ", f'name="{raw}"')
            yield Obs(subj, "host.name", name, Span(line, line, path=f"{hpath}/hostnames/hostname[{n}]"),
                      attrs={"type": clip_value(hn.get("type") or "unknown", 16)})
        yield from self._os(h, subj, hpath, loc, a, b)
        for n, port in enumerate(h.findall("ports/port"), 1):
            yield from self._port(port, n, subj, hpath, loc, a, b)
        for n, script in enumerate(h.findall("hostscript/script"), 1):
            sid = script.get("id") or ""
            line = loc.find(a, b, "<script", f'id="{sid}"')
            yield from self._script(script, subj, None, f"{hpath}/hostscript/script[{n}]", line)

    def _os(self, h: Any, subj: Ref, hpath: str, loc: _Locator, a: int, b: int) -> Iterator[Obs]:
        best: Any = None
        best_acc = -1
        best_n = 0
        for n, m in enumerate(h.findall("os/osmatch"), 1):
            try:
                acc = int(m.get("accuracy") or "0")
            except ValueError:
                acc = 0
            if acc > best_acc:
                best, best_acc, best_n = m, acc, n
        if best is None or not best.get("name"):
            return
        name = clip_value(best.get("name") or "", 256)
        line = loc.find(a, b, "<osmatch", f'accuracy="{best_acc}"')
        attrs = {"accuracy": str(max(0, best_acc))}
        cls = best.find("osclass")
        if cls is not None:
            if cls.get("osfamily"):
                attrs["osfamily"] = clip_value(cls.get("osfamily") or "", 64)
            cpe = cls.find("cpe")
            if cpe is not None and cpe.text:
                attrs["cpe"] = clip_value(cpe.text, 256)
        conf = round(0.95 * min(100, max(0, best_acc)) / 100, 4)
        yield Obs(subj, "host.os", name, Span(line, line, path=f"{hpath}/os/osmatch[{best_n}]"),
                  confidence=conf, attrs=attrs)

    def _port(self, p: Any, n: int, subj: Ref, hpath: str, loc: _Locator, a: int, b: int
              ) -> Iterator[Obs | Mention]:
        proto = (p.get("protocol") or "").lower()
        try:
            portid = int(p.get("portid") or "")
        except ValueError:
            return
        if proto not in _PROTOS or not 0 <= portid <= 65535:
            return
        svc = Ref.service(subj, proto, portid)
        ppath = f"{hpath}/ports/port[{n}]"
        line = loc.find(a, b, "<port ", f'portid="{portid}"', f'protocol="{proto}"')
        st = p.find("state")
        if st is not None and st.get("state"):
            attrs = {"reason": clip_value(st.get("reason") or "", 64)} if st.get("reason") else {}
            yield Obs(svc, "service.state", clip_value(st.get("state") or "", 32).lower(),
                      Span(line, line, path=f"{ppath}/state"), attrs=attrs)
        s = p.find("service")
        if s is not None:
            sline = loc.find(line, b, "<service")
            span = Span(sline, sline, path=f"{ppath}/service")
            method = (s.get("method") or "").lower()
            conf = 0.3 if method == "table" else None
            meta = {k: clip_value(s.get(k) or "", 32) for k in ("method", "conf") if s.get(k)}
            if s.get("ostype"):
                meta["ostype"] = clip_value(s.get("ostype") or "", 64)
            if s.get("name"):
                yield Obs(svc, "service.name", clip_value(s.get("name") or "", 64), span,
                          confidence=conf, attrs=meta)
            for attr, pred in (("product", "service.product"), ("version", "service.version"),
                               ("extrainfo", "service.extrainfo"), ("tunnel", "service.tunnel")):
                val = s.get(attr)
                if val and val.strip():
                    yield Obs(svc, pred, clip_value(val, 256), span, confidence=conf, attrs=meta)
            hn = valid_hostname(s.get("hostname"))
            if hn:
                yield Obs(subj, "host.name", hn, span, confidence=conf, attrs={"type": "service_info"})
            for c in s.findall("cpe"):
                if c.text and c.text.strip().lower().startswith("cpe:"):
                    yield Obs(svc, "service.cpe", clip_value(c.text, 256).lower(), span, confidence=conf)
        for k, script in enumerate(p.findall("script"), 1):
            sid = script.get("id") or ""
            sline = loc.find(line, b, "<script", f'id="{sid}"')
            yield from self._script(script, subj, svc, f"{ppath}/script[{k}]", sline)

    # ---------------------------------------------------------------- scripts
    def _script(self, s: Any, host: Ref, svc: Ref | None, path: str, line: int
                ) -> Iterator[Obs | Mention]:
        sid = s.get("id") or ""
        if not sid or len(sid) > 64:
            return
        output = s.get("output") or ""
        span = Span(line, line, path=path)
        attrs = {"output": clip_value(output, MAX_SCRIPT_OUTPUT)} if output.strip() else {}
        if svc is not None:
            yield Obs(svc, "service.script", sid, span, attrs=attrs)
        else:
            yield Obs(host, "host.script", sid, span, attrs=attrs)
        if sid == "ssh-hostkey":
            yield from self._ssh_hostkey(s, host, svc, span)
        elif sid == "smb-os-discovery":
            yield from self._smb_os(s, host, span)
        elif sid == "ssl-cert" and svc is not None:
            yield from self._ssl_cert(s, output, svc, span)
        elif sid == "nbstat":
            nb = nbstat_name(output)
            if nb:
                yield Obs(host, "host.netbios", nb, span)

    def _ssh_hostkey(self, s: Any, host: Ref, svc: Ref | None, span: Span) -> Iterator[Obs]:
        for t in s.findall("table"):
            m = _elem_map(t)
            ktype = ssh_key_type(m.get("type", ""))
            if not ktype:
                continue
            fp = ssh_fingerprint(m["key"]) if m.get("key") else None
            md5 = _md5_colons(m.get("fingerprint", ""))
            attrs = {"bits": m["bits"]} if m.get("bits", "").isdigit() else {}
            if md5:
                attrs["md5"] = md5
            if svc is not None:
                attrs["service"] = svc.key
            # SHA256 wie ssh-keygen; MD5 zusätzlich, damit Funde aus der Normalausgabe
            # (dort gibt es nur MD5) dieselbe Kennung ergeben
            for ident in (fp, f"MD5:{md5}" if md5 else None):
                if ident is None:
                    continue
                if svc is not None:
                    yield Obs(svc, "service.ssh_hostkey", f"{ktype} {ident}", span, attrs=attrs)
                yield Obs(host, "host.sshkey", Ref.sshkey(ktype, ident), span, attrs=attrs)

    def _smb_os(self, s: Any, host: Ref, span: Span) -> Iterator[Obs]:
        m = _elem_map(s)
        os_name = _strip_nul(m.get("os"))
        lanman = _strip_nul(m.get("lanmanager"))
        if os_name and lanman:
            yield Obs(host, "host.smb_os", clip_value(f"{os_name} ({lanman})", 256), span)
        elif os_name or lanman:
            yield Obs(host, "host.smb_os", clip_value(os_name or lanman, 256), span)
        nb = _strip_nul(m.get("server"))
        if nb and " " not in nb and len(nb) <= 32:
            yield Obs(host, "host.netbios", nb.upper(), span)
        fqdn = valid_hostname(_strip_nul(m.get("fqdn")))
        if fqdn:
            yield Obs(host, "host.name", fqdn, span, attrs={"type": "smb"})
        dom = _strip_nul(m.get("domain_dns"))
        if dom:
            yield Obs(host, "host.domain", clip_value(dom.lower(), 253), span)
        wg = _strip_nul(m.get("domain")) or _strip_nul(m.get("workgroup"))
        if wg:
            yield Obs(host, "host.smb_domain", clip_value(wg.upper(), 64), span)

    def _ssl_cert(self, s: Any, output: str, svc: Ref, span: Span) -> Iterator[Obs]:
        seen: set[str] = set()
        for t in s.findall("table"):
            if t.get("key") == "subject":
                cn = _elem_map(t).get("commonName")
                if cn and cn.strip():
                    seen.add(clip_value(cn, 253).lower())
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("Subject Alternative Name:"):
                for part in line.split(":", 1)[1].split(","):
                    part = part.strip()
                    if part.startswith("DNS:") and part[4:].strip():
                        seen.add(clip_value(part[4:], 253).lower())
        for name in sorted(seen):
            yield Obs(svc, "service.tls_cn", name, span)


def _mac(raw: str) -> str | None:
    s = raw.strip().lower().replace("-", ":")
    parts = s.split(":")
    if len(parts) != 6 or any(len(p) != 2 or any(c not in "0123456789abcdef" for c in p) for p in parts):
        return None
    return s
