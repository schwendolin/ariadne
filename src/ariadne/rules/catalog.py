"""Regelkatalog v0.1 (Architektur 6.1, E64, ``docs/web-api.md`` 18.6, ``docs/denkanstoesse.md``).

Jede Regel ist eine Funktion über :class:`~ariadne.rules.facts.Facts` und liefert
:class:`Candidate`-Objekte: Subjekt (Host oder Dienst), natürliche Schlüssel, Fingerabdruck des
Anlasses (``basis``), Titel und Begründung in Teilen (Zieldaten markiert), Lernstufen, Belege, die
Vorlagen aus der Bibliothek und ihre Rohwerte. Regeln kennen keine Befehlszeilen; ob eine Prüfung
schon gemacht ist, fragen sie die Erkenner (:mod:`ariadne.rules.commands`).

Regel-IDs und Prüfziel-IDs sind stabil. Eine Regel erzeugt nur Vorschläge, nie Fakten, und
Ariadne führt nie etwas davon aus (E10).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache, partial

from ariadne.rules import commands as C
from ariadne.rules.facts import ClaimRef, Facts, Host, Service

__all__ = ["Rule", "Candidate", "Detail", "CATALOG", "RULES"]

# --------------------------------------------------------------------------- Typen


@dataclass(frozen=True)
class Rule:
    rule_id: str
    goal_id: str | None
    kind: str  # goal | question | hypothesis | hint
    priority: int
    login_attempt: bool  # Vorlagen versuchen eine Anmeldung: nur im Profil lab (A 6.4 Punkt 8)
    fn: Callable[[Facts], Iterable[Candidate]]


@dataclass(slots=True)
class Detail:
    """Was ein Denkanstoss zeigt: Titel und Begründung in Teilen (Zieldaten markiert), Lernstufen, Belege,
    Vorlagen der Bibliothek und ihre Rohwerte, Kennzeichen."""

    title: list[tuple[str, bool]]
    reason: list[tuple[str, bool]]
    question: str
    direction: str
    evidence: list[ClaimRef]
    templates: list[str]
    slots: dict[str, object] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)


@dataclass(slots=True)
class Candidate:
    """Ein Denkanstoss vor dem Ausliefern: Subjekt, natürliche Schlüssel, Anlass; Details erst bei Bedarf."""

    rule: Rule
    host: Host
    service: Service | None
    natural: tuple[str, ...]  # (Subjekt-Kennung, Zusatz …)
    basis: tuple[str, ...]
    make: Callable[[], Detail]
    _detail: Detail | None = None

    @property
    def detail(self) -> Detail:
        if self._detail is None:
            self._detail = self.make()
        return self._detail

    @property
    def ts(self) -> int | None:
        stamps = [c.last_ts for c in self.detail.evidence if c.last_ts is not None]
        return max(stamps) if stamps else None

    @property
    def port(self) -> int:
        return self.service.port if self.service is not None else -1


# --------------------------------------------------------------------------- Hilfen

_PLAIN = re.compile(r"[A-Za-z0-9 ._+-]{1,40}")
_VERSION_TOKEN = re.compile(r"v?\d+(?:\.\d+)*[A-Za-z0-9.+_~-]*")
_DISTRO_CUT = re.compile(r"(\d+(?:\.\d+)+[a-z0-9]*)-.*")
_SAMBA = re.compile(r"Samba ([^\s)]+)")
_GENERIC_WORDS = frozenset({"httpd", "smbd", "smtpd", "daemon", "server", "engine", "service"})

FTP_NAMES = frozenset({"ftp", "ftps", "ssl/ftp"})
SMB_NAMES = frozenset({"netbios-ssn", "microsoft-ds", "smb", "cifs"})
NFS_NAMES = frozenset({"nfs", "mountd", "nfs_acl"})
SMTP_NAMES = frozenset({"smtp", "smtps", "submission", "ssl/smtp"})
DB_NAMES = {
    "mysql": "mysql",
    "postgresql": "postgresql",
    "ms-sql-s": "mssql",
    "ms-sql-m": "mssql",
    "oracle-tns": "oracle",
    "oracle": "oracle",
    "mongodb": "mongodb",
    "mongod": "mongodb",
    "redis": "redis",
}
DB_LABEL = {
    "mysql": "MySQL",
    "postgresql": "PostgreSQL",
    "mssql": "MS-SQL",
    "oracle": "Oracle",
    "mongodb": "MongoDB",
    "redis": "Redis",
}
DB_PORTS = {"mysql": 3306, "postgresql": 5432, "mssql": 1433, "oracle": 1521, "mongodb": 27017, "redis": 6379}
DB_TEMPLATES = {
    "mysql": ["mysql-root-nopass", "nmap-mysql-empty-password"],
    "postgresql": ["psql-postgres"],
    "mssql": ["nmap-ms-sql-empty-password"],
    "oracle": [],
    "mongodb": ["nmap-mongodb-info"],
    "redis": ["redis-info"],
}
DB_SCRIPTS = {
    "mysql": ("mysql-empty-password", "mysql-brute"),
    "postgresql": ("pgsql-brute",),
    "mssql": ("ms-sql-empty-password",),
    "oracle": (),
    "mongodb": ("mongodb-info",),
    "redis": ("redis-info",),
}
DB_TOOLS = {
    "mysql": {"mysql", "mariadb"},
    "postgresql": {"psql"},
    "mssql": {"mssqlclient", "sqsh", "sqlcmd"},
    "oracle": {"odat", "sqlplus"},
    "mongodb": {"mongo", "mongosh"},
    "redis": {"redis-cli"},
}
BRUTE_TOOLS = frozenset({"hydra", "medusa", "ncrack", "patator"})
NXC = frozenset({"nxc", "netexec", "crackmapexec", "cme"})
WEB_TOOLS = frozenset(
    {
        "gobuster",
        "feroxbuster",
        "dirb",
        "dirsearch",
        "ffuf",
        "wfuzz",
        "nikto",
        "whatweb",
        "wpscan",
        "curl",
        "wget",
        "httpx",
        "katana",
        "hakrawler",
        "eyewitness",
        "aquatone",
    }
)


def _ip_text(h: Host) -> str:
    ip = h.ip
    if ip is None:
        return h.label
    return f"[{ip}]" if ":" in ip else ip


def _at(h: Host, s: Service) -> str:
    return f"{_ip_text(h)}:{s.port}"


@lru_cache(maxsize=8192)
def _plain(value: str | None) -> str | None:
    return value if value is not None and _PLAIN.fullmatch(value) else None


def is_web(s: Service) -> bool:
    n = s.name or ""
    if n in ("ajp13", "http-rpc-epmap", "ncacn_http"):
        return False
    return n.startswith("http") or n.endswith("/http") or n.startswith("ssl/http") or n == "www"


def scheme(s: Service) -> str:
    n = s.name or ""
    tunnel = (s.value("service.tunnel") or "").lower()
    return "https" if tunnel == "ssl" or n in ("https", "https-alt") or n.startswith("ssl/") else "http"


def is_ftp(s: Service) -> bool:
    n = s.name
    if n is not None:
        return n in FTP_NAMES
    return bool(re.search(r"ftpd?\b", s.value("service.product") or "", re.I)) and s.proto == "tcp"


def is_smb(s: Service) -> bool:
    if s.proto != "tcp":
        return False
    n = s.name
    return n in SMB_NAMES if n is not None else s.port in (139, 445)


def is_nfs(s: Service) -> bool:
    n = s.name
    return n in NFS_NAMES if n is not None else s.port == 2049


def db_class(s: Service) -> str | None:
    return DB_NAMES.get(s.name or "")


def cred_class(s: Service) -> str | None:
    n = s.name or ""
    product = s.value("service.product") or ""
    if is_web(s) and re.search(r"tomcat|coyote", product, re.I):
        return "tomcat"
    if n.startswith("vnc"):
        return "vnc"
    if n == "telnet":
        return "telnet"
    if n == "snmp":
        return "snmp"
    return None


def _open(f: Facts) -> Iterator[tuple[Host, Service]]:
    for h in f.hosts.values():
        for s in h.open_services:
            yield h, s


def _classes(f: Facts) -> dict[str, list[tuple[Host, Service]]]:
    """Offene Dienste nach Klasse, einmal pro Anfrage (statt in jeder Regel neu zu prüfen)."""
    got: dict[str, list[tuple[Host, Service]]] | None = f.memo.get("classes")
    if got is None:
        got = {k: [] for k in ("smb", "ftp", "nfs", "web", "cred", "db", "smtp", "product")}
        for h, s in _open(f):
            if is_smb(s):
                got["smb"].append((h, s))
            elif is_ftp(s):
                got["ftp"].append((h, s))
            if is_nfs(s):
                got["nfs"].append((h, s))
            if is_web(s):
                got["web"].append((h, s))
            if cred_class(s) is not None:
                got["cred"].append((h, s))
            if db_class(s) is not None:
                got["db"].append((h, s))
            if (s.name or "") in SMTP_NAMES:
                got["smtp"].append((h, s))
            if s.one("service.product") is not None:
                got["product"].append((h, s))
        f.memo["classes"] = got
    return got


def _claims(*refs: ClaimRef | None) -> list[ClaimRef]:
    return [r for r in refs if r is not None][:5]


def _flags(refs: Iterable[ClaimRef]) -> set[str]:
    out: set[str] = set()
    for r in refs:
        if r.from_target:
            out.add("from_target")
        if r.suspect:
            out.add("injection_suspect")
    return out


# --------------------------------------------------------------------------- Erkenner


def _observed_script(f: Facts, units: Iterable[str], script: str) -> bool:
    """Hat ein beobachtender nmap-Lauf das Skript ausgeführt (auch ohne Ausgabe)?"""
    return any(f.ran_script(uid, script) for uid in units)


def _tool_hit(
    f: Facts,
    h: Host,
    tools: Iterable[str],
    *,
    port: int | None = None,
    default_ports: Iterable[int] = (),
    pred: Callable[[C.Cmd], bool] | None = None,
) -> bool:
    """Gibt es einen Befehl mit einem dieser Werkzeuge gegen den Host (und, wenn ``port`` gesetzt,
    gegen diesen Port: genannt oder, ohne genannten Port, einer der Standardports)?"""
    tools = frozenset(tools)
    for c in f.host_cmds(h.host_id):
        if c.tool not in tools or (pred is not None and not pred(c)):
            continue
        if port is None:
            return True
        explicit = C.ports(c.args, c.tool)
        if port in explicit or (not explicit and port in set(default_ports)):
            return True
    return False


def _covered(
    f: Facts,
    h: Host,
    s: Service | None,
    scripts: Iterable[str],
    *,
    tools: Iterable[str] = (),
    port: int | None = None,
    default_ports: Iterable[int] = (),
    pred: Callable[[C.Cmd], bool] | None = None,
) -> bool:
    """Erledigt-Erkennung in drei Stufen: Skriptausgabe da, beobachtender nmap-Lauf mit dem Skript,
    Befehl mit einem passenden Werkzeug gegen Host und Port (docs/denkanstoesse.md 4)."""
    scripts = tuple(scripts)
    pool = h.scripts if s is None else s.scripts
    if any(sc in pool for sc in scripts):
        return True
    observers = h.observers if s is None else s.observers
    if any(_observed_script(f, observers, sc) for sc in scripts):
        return True
    return bool(tools) and _tool_hit(f, h, tools, port=port, default_ports=default_ports, pred=pred)


def _nxc_proto(proto: str) -> Callable[[C.Cmd], bool]:
    return lambda c: bool(c.args) and c.args[0].lower() == proto


# --------------------------------------------------------------------------- Regeln
#
# Jede Regel prüft sofort (Auslöser, Ausschlüsse, Erledigt-Erkennung) und liefert Subjekt, Schlüssel und
# Anlass. Titel, Begründung, Lernstufen, Belege und Vorlagenwerte baut eine Detailfunktion erst beim
# Ausliefern (``Candidate.detail``): ``open_count`` braucht sie nie, ``/next`` nur für 50 Einträge.

_ANON_Q = "Welche Daten gibt dieser Dienst ohne Anmeldung preis?"


def _d_anon_ftp(h: Host, s: Service) -> Detail:
    product = s.value("service.product")
    word = _plain(product.split(" ")[0] if product else None)
    name = s.one("service.name")
    return Detail(
        title=[("Unauthentisierten Zugriff auf ", False), (_at(h, s), True), (" prüfen", False)],
        reason=[("FTP-Dienst ohne geprüfte anonyme Anmeldung", False)],
        question=_ANON_Q,
        direction=(
            f"Viele {word}-Installationen erlauben Gast- oder anonyme Logins."
            if word
            else "Viele FTP-Server erlauben Gast- oder anonyme Logins."
        ),
        evidence=_claims(name),
        templates=["nmap-ftp-anon", "ftp-client"],
        slots={"host.ip": h.ip, "service.port": s.port},
        flags=_flags(_claims(name, s.one("service.product"))),
    )


def _d_anon_smb(h: Host, s: Service, svcs: list[Service]) -> Detail:
    names = _claims(*(x.one("service.name") for x in sorted(svcs, key=lambda x: x.port)))
    return Detail(
        title=[("Unauthentisierten Zugriff auf ", False), (_at(h, s), True), (" prüfen", False)],
        reason=[("SMB-Dienst ohne geprüfte Null-Session", False)],
        question=_ANON_Q,
        direction=(
            "Ältere Samba- und Windows-Versionen erlauben Null-Sessions ohne Konto; damit lassen "
            "sich Benutzer und Freigaben abfragen."
        ),
        evidence=names,
        templates=["rpcclient-null", "nxc-smb-null"],
        slots={"host.ip": h.ip},
        flags=_flags(names),
    )


_FTP_CLIENTS = frozenset({"ftp", "lftp", "ncftp", "ftp-ssl"})
_SMB_TOOLS = frozenset({"smbclient", "rpcclient", "smbmap", "enum4linux", "enum4linux-ng"})
_SMB_ANON_SCRIPTS = ("smb-security-mode", "smb-os-discovery", "smb-enum-shares", "smb-enum-users")


def _ftp_url(c: C.Cmd) -> bool:
    return any(a.lower().startswith("ftp://") for a in c.args)


def _anon(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-ANON-ZUGRIFF"]
    smb_hosts: dict[str, list[Service]] = {}
    for h, s in _classes(f)["smb"]:
        smb_hosts.setdefault(h.host_id, []).append(s)
    for h, s in _classes(f)["ftp"]:
        if (
            _covered(f, h, s, ("ftp-anon",), tools=_FTP_CLIENTS, port=s.port, default_ports=(21,))
            or _tool_hit(f, h, {"curl", "wget"}, port=s.port, default_ports=(21,), pred=_ftp_url)
            or _tool_hit(f, h, NXC, port=s.port, default_ports=(21,), pred=_nxc_proto("ftp"))
        ):
            continue
        product = s.value("service.product")
        yield Candidate(rule, h, s, (s.service_id,), ("ftp", product or ""), partial(_d_anon_ftp, h, s))
    for hid, svcs in smb_hosts.items():
        h = f.hosts[hid]
        s = max(svcs, key=lambda x: (x.port == 445, -x.port))
        if any(sc in h.scripts for sc in _SMB_ANON_SCRIPTS):
            continue
        observers = set().union(*(x.observers for x in svcs))
        if any(_observed_script(f, observers, sc) for sc in _SMB_ANON_SCRIPTS):
            continue
        if _tool_hit(f, h, _SMB_TOOLS) or _tool_hit(f, h, NXC, pred=_nxc_proto("smb")):
            continue
        yield Candidate(rule, h, s, (h.host_id, "class:smb"), ("smb",), partial(_d_anon_smb, h, s, svcs))


@lru_cache(maxsize=8192)
def _precise(version: str | None) -> str | None:
    """Erstes Wort einer genauen Version (``2.3.4``, ``4.7p1``), sonst ``None`` (Bereich ``3.X - 4.X``)."""
    if not version or " - " in version or re.search(r"\bX\b|\.X\b|\bx\b", version):
        return None
    first = version.split(" ")[0]
    return first if _VERSION_TOKEN.fullmatch(first) else None


@lru_cache(maxsize=8192)
def _search_words(product: str) -> str:
    """Suchbegriffe aus dem Produkt: ``/`` und Leerzeichen trennen, allgemeine Wörter (``httpd``)
    weglassen. Nicht druckbares ASCII bleibt unverändert (der Encoder sperrt es)."""
    if not (product.isascii() and product.isprintable()):
        return product
    words = [w for w in re.split(r"[ /]+", product) if w]
    kept = [w for w in words if w.lower() not in _GENERIC_WORDS]
    return " ".join(kept or words) or product


@lru_cache(maxsize=8192)
def _search_version(version: str) -> str:
    if not (version.isascii() and version.isprintable()):
        return version
    first = version.split(" ")[0]
    m = _DISTRO_CUT.fullmatch(first)
    return m.group(1) if m else first


def _d_version(h: Host, s: Service, product: str, version: str, refs: list[ClaimRef]) -> Detail:
    return Detail(
        title=[
            ("Version recherchieren: ", False),
            (f"{product} {version}", True),
            (" (", False),
            (_at(h, s), True),
            (")", False),
        ],
        reason=[("Produkt und Version bekannt: ", False), (f"{product} {version}", True)],
        question="Gibt es für diese Version bekannte Schwachstellen?",
        direction=(
            "Exploit-Datenbanken nach Produkt und Version durchsuchen; Treffer immer an der genauen "
            "Version prüfen."
        ),
        evidence=refs,
        templates=["searchsploit"],
        slots={"service.product": _search_words(product), "service.version": _search_version(version)},
        flags=_flags(refs),
    )


def _version(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-VERSION-RECHERCHE"]
    groups: dict[tuple[str, str, str], list[tuple[Service, str, str, list[ClaimRef], bool]]] = {}
    for h, s in _classes(f)["product"]:
        prod = s.one("service.product")
        if prod is None:
            continue
        ver = s.one("service.version")
        version = ver.value if ver is not None and _precise(ver.value) else None
        refs = _claims(ver, prod)
        derived = False
        if version is None and is_smb(s) and "samba" in prod.value.lower():
            smb_os = h.one("host.smb_os")
            m = _SAMBA.search(smb_os.value) if smb_os is not None else None
            if m and _precise(m.group(1)):
                version, refs, derived = m.group(1), _claims(smb_os, prod), True
        if version is None:
            continue
        key = (h.host_id, _search_words(prod.value).lower(), _search_version(version))
        groups.setdefault(key, []).append((s, prod.value, version, refs, derived))
    for key, group in groups.items():
        # Subjekt: eigener genauer Wert vor abgeleitetem (smb_os), SMB auf 445 zuerst, dann der kleinste Port
        members = sorted(
            group, key=lambda m: (m[4], not (is_smb(m[0]) and m[0].port == 445), m[0].proto, m[0].port)
        )
        s, product, version, refs, _derived = members[0]
        h = f.hosts[key[0]]
        if _searchsploit_any(f, product.split(" ")[0]):
            continue
        if any(_observed_script(f, m[0].observers, "vulners") for m in members):
            continue
        yield Candidate(
            rule, h, s, (s.service_id,), (product, version), partial(_d_version, h, s, product, version, refs)
        )


def _searchsploit_any(f: Facts, first_word: str) -> bool:
    """``searchsploit vsftpd`` ohne Ziel-Adresse zählt für jedes Produkt, dessen erstes Wort darin steht."""
    w = first_word.lower()
    if len(w) < 3:
        return False
    return any(w in a for a in f.searchsploit_args())


def _by_host(f: Facts, cls: str) -> dict[str, list[Service]]:
    out: dict[str, list[Service]] = {}
    for h, s in _classes(f)[cls]:
        out.setdefault(h.host_id, []).append(s)
    return out


def _ports(svcs: list[Service]) -> str:
    return ", ".join(str(x.port) for x in sorted(svcs, key=lambda x: x.port))


def _d_shares(h: Host, s: Service, svcs: list[Service]) -> Detail:
    names = _claims(*(x.one("service.name") for x in sorted(svcs, key=lambda x: x.port)))
    return Detail(
        title=[("SMB-Shares auf ", False), (_ip_text(h), True), (" auflisten", False)],
        reason=[(f"SMB auf Port {_ports(svcs)} ohne Liste der Shares", False)],
        question="Welche Freigaben bietet dieser Host an, und welche sind ohne Anmeldung lesbar?",
        direction=(
            "Freigaben lassen sich oft ohne Konto auflisten; eine beschreibbare Freigabe ist ein häufiger "
            "Einstieg."
        ),
        evidence=names,
        templates=["smbclient-list", "smbmap", "nmap-smb-enum-shares"],
        slots={"host.ip": h.ip, "service.port": s.port},
        flags=_flags(names),
    )


def _smbclient_list(c: C.Cmd) -> bool:
    return any(a in ("-L", "--list") or a.startswith("--list=") for a in c.args)


def _nxc_shares(c: C.Cmd) -> bool:
    return _nxc_proto("smb")(c) and "--shares" in c.args


def _smb_shares(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-SMB-SHARES"]
    for hid, svcs in _by_host(f, "smb").items():
        h = f.hosts[hid]
        s = max(svcs, key=lambda x: (x.port == 445, -x.port))
        if "smb-enum-shares" in h.scripts or any(
            _observed_script(f, x.observers, "smb-enum-shares") for x in svcs
        ):
            continue
        if (
            _tool_hit(f, h, {"smbclient"}, pred=_smbclient_list)
            or _tool_hit(f, h, {"smbmap", "enum4linux", "enum4linux-ng"})
            or _tool_hit(f, h, NXC, pred=_nxc_shares)
        ):
            continue
        yield Candidate(rule, h, s, (h.host_id,), ("smb", _ports(svcs)), partial(_d_shares, h, s, svcs))


def _d_nfs(h: Host, s: Service, svcs: list[Service]) -> Detail:
    names = _claims(*(x.one("service.name") for x in sorted(svcs, key=lambda x: x.port)))
    return Detail(
        title=[("NFS-Exporte von ", False), (_ip_text(h), True), (" auflisten", False)],
        reason=[(f"NFS auf Port {_ports(svcs)} ohne Liste der Exporte", False)],
        question="Welche Verzeichnisse exportiert dieser Host, und für welche Clients?",
        direction=(
            "Exporte für alle Clients (*) lassen sich ohne Anmeldung einhängen; bei NFS ist das die Prüfung "
            "auf Zugriff ohne Anmeldung."
        ),
        evidence=names,
        templates=["showmount", "nmap-nfs-showmount"],
        slots={"host.ip": h.ip},
        flags=_flags(names),
    )


def _mount_nfs(c: C.Cmd) -> bool:
    return any("nfs" in a.lower() for a in c.args)


def _nfs(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-NFS-EXPORTS"]
    scripts = ("nfs-showmount", "nfs-ls")
    for hid, svcs in _by_host(f, "nfs").items():
        h = f.hosts[hid]
        s = min(svcs, key=lambda x: (x.port != 2049, x.port))
        if any(sc in h.scripts or any(sc in x.scripts for x in svcs) for sc in scripts):
            continue
        if any(_observed_script(f, h.observers, sc) for sc in scripts):
            continue
        if (
            _tool_hit(f, h, {"showmount"})
            or _tool_hit(f, h, {"mount"}, pred=_mount_nfs)
            or _tool_hit(f, h, NXC, pred=_nxc_proto("nfs"))
        ):
            continue
        yield Candidate(rule, h, s, (h.host_id,), ("nfs", _ports(svcs)), partial(_d_nfs, h, s, svcs))


def _d_web(h: Host, s: Service, sch: str) -> Detail:
    name = _claims(s.one("service.name"))
    ip = h.ip
    host_part = f"[{ip}]" if ip and ":" in ip else ip
    return Detail(
        title=[("Webinhalt auf ", False), (_at(h, s), True), (" untersuchen", False)],
        reason=[("Webdienst ohne Prüfung von Inhalt und Verzeichnissen", False)],
        question="Was liefert dieser Webdienst ausser der Startseite?",
        direction=(
            "Verzeichnisse und Dateien raten, Kopfzeilen und Technik bestimmen; Admin-Bereiche und "
            "Sicherungskopien sind häufige Funde."
        ),
        evidence=name,
        templates=["curl-head", "whatweb", "gobuster-dir", "nikto"],
        slots={"service.url": f"{sch}://{host_part}:{s.port}/" if host_part else None},
        flags=_flags(name),
    )


def _web(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-WEB-INHALT"]
    for h, s in _classes(f)["web"]:
        sch = scheme(s)
        defaults = (443,) if sch == "https" else (80,)
        if _covered(f, h, s, ("http-enum",), tools=WEB_TOOLS, port=s.port, default_ports=defaults):
            continue
        yield Candidate(rule, h, s, (s.service_id,), ("web", sch), partial(_d_web, h, s, sch))


_CRED_TEXT = {
    "tomcat": (
        "Der Tomcat-Manager wird oft mit Standardkonten betrieben",
        ["nmap-http-default-accounts"],
        ("http-default-accounts",),
        frozenset(),
        (),
    ),
    "vnc": (
        "VNC-Server sind oft nur mit einem schwachen oder leeren Passwort geschützt",
        ["vncviewer"],
        ("vnc-brute",),
        frozenset({"vncviewer", "xtightvncviewer", "xvncviewer"}),
        (5900,),
    ),
    "telnet": (
        "Telnet-Zugänge in Labs haben oft Standardkonten",
        ["telnet-client"],
        ("telnet-brute",),
        frozenset({"telnet"}),
        (23,),
    ),
    "snmp": (
        "SNMP-Agenten antworten oft auf die Community public",
        ["snmpwalk-public"],
        ("snmp-brute",),
        frozenset({"snmpwalk", "snmpget", "snmpbulkwalk", "onesixtyone", "snmp-check"}),
        (161,),
    ),
}


def _d_creds(h: Host, s: Service, cls: str) -> Detail:
    reason, templates, _scripts, _tools, _defaults = _CRED_TEXT[cls]
    ref = _claims(s.one("service.product") if cls == "tomcat" else s.one("service.name"))
    return Detail(
        title=[("Gibt es auf ", False), (_at(h, s), True), (" Standardkonten?", False)],
        reason=[(reason, False)],
        question="Welche Standardkonten liefert der Hersteller aus, und sind sie noch aktiv?",
        direction=(
            "Die Dokumentation des Produkts nennt die Standardkonten. Bei Anmeldeversuchen an "
            "Kontosperren denken."
        ),
        evidence=ref,
        templates=list(templates),
        slots={"host.ip": h.ip, "service.port": s.port},
        flags=_flags(ref),
    )


def _creds(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-STANDARD-CREDS"]
    for h, s in _classes(f)["cred"]:
        cls = cred_class(s)
        if cls is None:
            continue
        _reason, _templates, scripts, tools, defaults = _CRED_TEXT[cls]
        if _covered(f, h, s, scripts, tools=tools | BRUTE_TOOLS, port=s.port, default_ports=defaults):
            continue
        if _tool_hit(f, h, NXC, port=s.port, default_ports=defaults):
            continue
        yield Candidate(rule, h, s, (s.service_id,), (cls,), partial(_d_creds, h, s, cls))


def _d_smtp(h: Host, s: Service) -> Detail:
    name = _claims(s.one("service.name"))
    return Detail(
        title=[("Lassen sich über SMTP auf ", False), (_at(h, s), True), (" Benutzer ermitteln?", False)],
        reason=[("SMTP-Dienst ohne Prüfung auf Benutzer-Enumeration", False)],
        question="Verrät der Mailserver, welche Benutzer es gibt?",
        direction="Die SMTP-Befehle VRFY, EXPN und RCPT TO bestätigen oft vorhandene Konten.",
        evidence=name,
        templates=["smtp-user-enum-vrfy", "nmap-smtp-enum-users"],
        slots={"host.ip": h.ip, "service.port": s.port},
        flags=_flags(name),
    )


def _smtp(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-SMTP-USER"]
    tools = frozenset({"smtp-user-enum", "ismtp"})
    for h, s in _classes(f)["smtp"]:
        if _covered(f, h, s, ("smtp-enum-users",), tools=tools, port=s.port, default_ports=(25,)):
            continue
        yield Candidate(rule, h, s, (s.service_id,), ("smtp",), partial(_d_smtp, h, s))


def _d_db(h: Host, s: Service, cls: str) -> Detail:
    name = _claims(s.one("service.name"))
    return Detail(
        title=[("Lässt die Datenbank auf ", False), (_at(h, s), True), (" eine Anmeldung zu?", False)],
        reason=[(f"{DB_LABEL[cls]}-Dienst ohne Anmeldeversuch", False)],
        question=(
            "Nimmt die Datenbank Verbindungen von aussen an, etwa mit einem Standardkonto ohne Passwort?"
        ),
        direction=(
            "Lab-Datenbanken erlauben oft root oder postgres ohne Passwort. Bei Erfolg liegen Konten und "
            "Hashes in den Systemtabellen."
        ),
        evidence=name,
        templates=list(DB_TEMPLATES[cls]),
        slots={"host.ip": h.ip, "service.port": s.port},
        flags=_flags(name),
    )


def _nxc_db(c: C.Cmd) -> bool:
    return bool(c.args) and c.args[0].lower() in ("mssql", "mysql", "postgres")


def _db(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-DB-ZUGRIFF"]
    for h, s in _classes(f)["db"]:
        cls = db_class(s)
        if cls is None:
            continue
        defaults = (DB_PORTS[cls],)
        if _covered(
            f, h, s, DB_SCRIPTS[cls], tools=DB_TOOLS[cls] | BRUTE_TOOLS, port=s.port, default_ports=defaults
        ):
            continue
        if _tool_hit(f, h, NXC, port=s.port, default_ports=defaults, pred=_nxc_db):
            continue
        yield Candidate(rule, h, s, (s.service_id,), ("db", cls), partial(_d_db, h, s, cls))


def _scanned(h: Host) -> list[Service]:
    """TCP-Dienste mit einem Zustand: der Host wurde nach Ports gescannt."""
    return [s for s in h.services if s.proto == "tcp" and s.one("service.state") is not None]


def _scan_evidence(h: Host) -> list[ClaimRef]:
    state = h.one("host.state")
    if state is not None:
        return [state]
    tcp = _scanned(h)
    return _claims(min(tcp, key=lambda s: s.port).one("service.state")) if tcp else []


def _full_cmd(c: C.Cmd) -> bool:
    if c.tool == "nmap":
        return C.nmap_opts(c.args).full_tcp
    if c.tool in ("masscan", "naabu"):
        spec = ",".join(c.args[i + 1] for i, a in enumerate(c.args[:-1]) if a in ("-p", "--ports", "--port"))
        spec += "," + ",".join(a[2:] for a in c.args if a.startswith("-p") and len(a) > 2)
        return any(p.strip() in ("-", "0-65535", "1-65535", "full") for p in spec.split(","))
    if c.tool == "rustscan":
        has_ports = any(
            a in ("-p", "--ports", "-r", "--range") or a.startswith(("--ports=", "--range=")) for a in c.args
        )
        if not has_ports:
            return True
        spec = ",".join(c.args[i + 1] for i, a in enumerate(c.args[:-1]) if a in ("-r", "--range"))
        return "1-65535" in spec or "0-65535" in spec
    return False


def _d_full(h: Host) -> Detail:
    ev = _scan_evidence(h)
    return Detail(
        title=[("Alle TCP-Ports von ", False), (_ip_text(h), True), (" scannen", False)],
        reason=[("Bisher nur die häufigsten TCP-Ports gescannt", False)],
        question="Laufen auf diesem Host Dienste ausserhalb der häufigsten 1000 Ports?",
        direction=(
            "Ein Scan über alle 65535 TCP-Ports findet Dienste auf ungewöhnlichen Ports, etwa Hintertüren "
            "oder Verwaltungsoberflächen."
        ),
        evidence=ev,
        templates=["nmap-full-tcp"],
        slots={"host.ip": h.ip},
        flags=_flags(ev),
    )


_SCAN_TOOLS = frozenset({"nmap", "masscan", "rustscan", "naabu"})


def _full(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-FULL-PORTSCAN"]
    for h in f.hosts.values():
        if not h.eligible or not _scanned(h):
            continue
        if any(_full_cmd(c) for uid in h.observers for c in f.unit_cmds(uid)):
            continue
        if _tool_hit(f, h, _SCAN_TOOLS, pred=_full_cmd):
            continue
        yield Candidate(rule, h, None, (h.host_id,), ("tcp-top",), partial(_d_full, h))


def _udp_cmd(c: C.Cmd) -> bool:
    if c.tool == "nmap":
        return C.nmap_opts(c.args).udp
    if c.tool == "unicornscan":
        pairs = zip(c.args, (*c.args[1:], ""), strict=True)
        return any(a.startswith("-mU") or (a == "-m" and b.startswith("U")) for a, b in pairs)
    return c.tool == "udpx"


def _d_udp(h: Host) -> Detail:
    ev = _scan_evidence(h)
    return Detail(
        title=[("UDP-Ports von ", False), (_ip_text(h), True), (" scannen", False)],
        reason=[("Noch kein UDP-Scan für diesen Host", False)],
        question="Welche Dienste laufen über UDP, etwa SNMP, TFTP oder DNS?",
        direction="Ein UDP-Scan der häufigsten Ports dauert länger als TCP, findet aber oft SNMP oder TFTP.",
        evidence=ev,
        templates=["nmap-udp-top"],
        slots={"host.ip": h.ip},
        flags=_flags(ev),
    )


_UDP_TOOLS = frozenset({"nmap", "unicornscan", "udpx"})


def _udp(f: Facts) -> Iterator[Candidate]:
    rule = RULES["R-UDP-SCAN"]
    for h in f.hosts.values():
        if not h.eligible or not _scanned(h) or any(s.proto == "udp" for s in h.services):
            continue
        if any(_udp_cmd(c) for uid in h.observers for c in f.unit_cmds(uid)):
            continue
        if _tool_hit(f, h, _UDP_TOOLS, pred=_udp_cmd):
            continue
        yield Candidate(rule, h, None, (h.host_id,), ("udp",), partial(_d_udp, h))


# --------------------------------------------------------------------------- Katalog

RULES: dict[str, Rule] = {}


def _rule(
    rule_id: str,
    goal: str,
    kind: str,
    prio: int,
    fn: Callable[[Facts], Iterable[Candidate]],
    *,
    login: bool = False,
) -> Rule:
    r = Rule(rule_id, goal, kind, prio, login, fn)
    RULES[rule_id] = r
    return r


CATALOG: tuple[Rule, ...] = (
    _rule("R-ANON-ZUGRIFF", "PZ-AUTH-ANON", "goal", 10, _anon),
    _rule("R-VERSION-RECHERCHE", "PZ-VULN-RECHERCHE", "goal", 20, _version),
    _rule("R-SMB-SHARES", "PZ-SMB-SHARES", "goal", 30, _smb_shares),
    _rule("R-NFS-EXPORTS", "PZ-NFS-EXPORTS", "goal", 31, _nfs),
    _rule("R-WEB-INHALT", "PZ-WEB-INHALT", "goal", 40, _web),
    _rule("R-STANDARD-CREDS", "PZ-CRED-DEFAULT", "question", 50, _creds, login=True),
    _rule("R-DB-ZUGRIFF", "PZ-DB-ZUGRIFF", "question", 51, _db, login=True),
    _rule("R-SMTP-USER", "PZ-SMTP-USER", "question", 60, _smtp),
    _rule("R-FULL-PORTSCAN", "PZ-PORTS-TCP", "goal", 70, _full),
    _rule("R-UDP-SCAN", "PZ-PORTS-UDP", "goal", 80, _udp),
)
