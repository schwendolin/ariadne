"""Ziele aus argv gängiger Tools (Aktivitätsprotokoll, Scope-Warnung; Architektur 5.13).

Liefert rohe Ziele (IP, CIDR, Bereich, Name, URL) so, wie sie im Befehl
stehen; normalisiert und geprüft wird später über ``ScopeMatcher``. Keine
DNS-Auflösung, keine Dateien lesen: Ziel-Listen (``nmap -iL``) erscheinen nur
als Hinweis in :attr:`Targets.input_files`.

Konservativ: Was sich nicht sicher als Ziel erkennen lässt, fehlt lieber.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from ariadne.ctxrules import strip_prefixes

__all__ = ["Targets", "analyze_targets", "extract_targets", "tool_name"]

_URLISH = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
_HOSTISH = re.compile(r"[A-Za-z0-9_.:\[\]%-]+(?:/\d{1,3})?")
_IPV4_RANGE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}-\d{1,3}(?:\.\d{1,3}){0,3}")
_MAX_TARGETS = 64


@dataclass
class Targets:
    targets: list[str] = field(default_factory=list)
    input_files: list[str] = field(default_factory=list)  # Ziel-Listen, nur als Hinweis

    def add(self, value: str | None) -> None:
        if value and value not in self.targets and len(self.targets) < _MAX_TARGETS:
            self.targets.append(value)

    def add_file(self, value: str | None) -> None:
        if value and value not in self.input_files:
            self.input_files.append(value)


def tool_name(argv: Sequence[str]) -> str:
    """Name des Tools ohne Wrapper, ``python3 x.py`` und ``impacket-``-Präfix."""
    args = strip_prefixes(list(argv))
    if not args:
        return ""
    head = os.path.basename(args[0])
    if head.startswith("python") and len(args) > 1 and args[1].endswith(".py"):
        head = os.path.basename(args[1])
    if head.endswith(".py"):
        head = head[:-3]
    if head.startswith("impacket-"):
        head = head[len("impacket-") :]
    return head


def _rest(argv: Sequence[str]) -> list[str]:
    args = strip_prefixes(list(argv))
    if args and os.path.basename(args[0]).startswith("python") and len(args) > 1 \
            and args[1].endswith(".py"):
        return args[2:]
    return args[1:]


def _positionals(args: Sequence[str], with_arg: set[str], *, long_eq: bool = True) -> list[str]:
    """Positionsargumente; Optionen aus ``with_arg`` verbrauchen das nächste Argument."""
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(args[i + 1 :])
            break
        if a.startswith("-") and len(a) > 1:
            if long_eq and a.startswith("--") and "=" in a:
                i += 1
                continue
            i += 2 if a in with_arg else 1
            continue
        out.append(a)
        i += 1
    return out


def _opt(args: Sequence[str], *names: str, attached: bool = True) -> list[str]:
    """Alle Werte einer Option (``-u X``, ``--url=X``, ``-uX`` für Kurzoptionen).

    ``attached=False`` für Tools mit langen Optionen nach einem Bindestrich
    (impacket: ``-tf`` ist nicht ``-t f``).
    """
    vals: list[str] = []
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                vals.append(args[i + 1])
            elif n.startswith("--") and a.startswith(n + "="):
                vals.append(a.split("=", 1)[1])
            elif (attached and len(n) == 2 and n[0] == "-" and a.startswith(n) and len(a) > 2
                  and not a.startswith("--")):
                vals.append(a[2:])
    return vals


def _host_of_userhost(s: str) -> str:
    return s.rsplit("@", 1)[-1]


def _looks_like_target(s: str) -> bool:
    if not s or s.startswith("-") or "=" in s:
        return False
    if _URLISH.fullmatch(s):
        return True
    return bool(_HOSTISH.fullmatch(s)) and any(c.isalnum() for c in s)


def _looks_like_file(s: str) -> bool:
    if _URLISH.fullmatch(s):
        return False
    return "/" in s and not re.fullmatch(r"[0-9a-fA-F:.]+/\d{1,3}", s) or s.endswith((".txt", ".lst"))


def _add_host_list(t: Targets, value: str) -> None:
    for part in value.split(","):
        part = part.strip()
        if _looks_like_target(part):
            t.add(part)


def _with_scheme(value: str) -> str:
    return value if "://" in value else "http://" + value


# --------------------------------------------------------------------------- Tools

_NMAP_ARG = {
    "-p", "-iL", "-iR", "--exclude", "--excludefile", "-e", "-S", "-D", "-g", "--source-port",
    "--script", "--script-args", "--script-args-file", "-sI", "-b", "--top-ports", "--min-rate",
    "--max-rate", "--data-length", "--ttl", "--spoof-mac", "--proxies", "--dns-servers",
    "--host-timeout", "--max-retries", "--scan-delay", "--max-scan-delay", "--min-parallelism",
    "--max-parallelism", "--min-hostgroup", "--max-hostgroup", "--initial-rtt-timeout",
    "--max-rtt-timeout", "--min-rtt-timeout", "--version-intensity", "--mtu", "--datadir",
    "--stylesheet", "--resume", "--exclude-ports", "--port-ratio", "--script-timeout", "--data",
    "--data-string", "--ip-options", "-oN", "-oX", "-oG", "-oA", "-oS", "-oM", "--stats-every",
    "--servicedb", "--versiondb", "--send-eth", "-T",
}


def _nmap(args: list[str], t: Targets) -> None:
    for f in _opt(args, "-iL"):
        t.add_file(f)
    for f in _opt(args, "--excludefile"):
        t.add_file(f)
    for p in _positionals(args, _NMAP_ARG):
        if _looks_like_target(p):
            t.add(p)


_SSH_ARG = {"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p",
            "-Q", "-R", "-S", "-W", "-w", "-B", "-P"}


def _ssh(args: list[str], t: Targets) -> None:
    for j in _opt(args, "-J"):
        for hop in j.split(","):
            hp = _host_of_userhost(hop)
            t.add(hp.rsplit(":", 1)[0] if hp.count(":") == 1 else hp)
    pos = _positionals(args, _SSH_ARG)
    if pos:
        target = pos[0]
        if target.startswith("ssh://"):
            t.add(target)
        else:
            t.add(_host_of_userhost(target))


_CURL_ARG = {
    "-o", "-H", "-d", "-X", "-u", "-A", "-e", "-b", "-c", "-x", "-F", "-T", "-w", "-K", "-m", "-E",
    "-r", "-C", "-U", "-Y", "-y", "-z", "-Q", "-t", "-D", "--data", "--data-raw", "--data-binary",
    "--data-urlencode", "--header", "--request", "--user", "--user-agent", "--referer", "--cookie",
    "--cookie-jar", "--proxy", "--form", "--upload-file", "--write-out", "--config", "--max-time",
    "--cert", "--key", "--cacert", "--capath", "--range", "--continue-at", "--proxy-user",
    "--resolve", "--connect-to", "--retry", "--connect-timeout", "--output", "--interface",
    "--dump-header", "--limit-rate", "--max-redirs", "--oauth2-bearer", "--url-query", "--json",
    "--unix-socket", "--abstract-unix-socket", "--trace", "--trace-ascii", "--stderr",
}


def _curl(args: list[str], t: Targets) -> None:
    for u in _opt(args, "--url"):
        t.add(_with_scheme(u))
    for p in _positionals(args, _CURL_ARG):
        if _looks_like_target(p) or _URLISH.match(p) or "/" in p:
            t.add(_with_scheme(p))


_WGET_ARG = {
    "-O", "-o", "-a", "-P", "-U", "-e", "-i", "-t", "-T", "-w", "-Q", "-l", "-B", "-D", "-R", "-A",
    "-I", "-X", "--header", "--user", "--password", "--post-data", "--post-file", "--user-agent",
    "--referer", "--load-cookies", "--save-cookies", "--output-document", "--directory-prefix",
    "--input-file", "--tries", "--timeout", "--wait", "--level", "--base", "--domains",
}


def _wget(args: list[str], t: Targets) -> None:
    for f in _opt(args, "-i", "--input-file"):
        t.add_file(f)
    for p in _positionals(args, _WGET_ARG):
        if _looks_like_target(p) or _URLISH.match(p) or "/" in p:
            t.add(_with_scheme(p))


def _url_tools(args: list[str], t: Targets) -> None:
    """gobuster, ffuf, feroxbuster, wpscan, sqlmap, whatweb, dirb."""
    for u in _opt(args, "-u", "--url", "-url", "--target"):
        t.add(_with_scheme(u))
    for d in _opt(args, "-d", "--domain"):
        if _looks_like_target(d):
            t.add(d)
    for f in _opt(args, "--urls", "--resume-from", "-request", "-r"):
        if _looks_like_file(f):
            t.add_file(f)


_URL_TOOL_ARG = {
    "-u", "--url", "-d", "--domain", "-w", "--wordlist", "-t", "--threads", "-s", "-b", "-o", "--output",
    "-x", "--extensions", "-X", "-H", "--headers", "-c", "--cookies", "-U", "--username", "-P",
    "--password", "-a", "--useragent", "-p", "--proxy", "-r", "-z", "-l", "-m", "--timeout",
    "--delay", "--log-verbose", "--user-agent", "--color", "--aggression",
}


def _url_positional(args: list[str], t: Targets) -> None:
    _url_tools(args, t)
    for p in _positionals(args, _URL_TOOL_ARG):
        if p.lower() in ("dir", "dns", "vhost", "fuzz", "s3", "gcs", "tftp"):
            continue
        if _URLISH.fullmatch(p) or _looks_like_target(p):
            t.add(_with_scheme(p))


_NXC_ARG = {
    "-u", "-p", "-H", "-d", "--port", "-t", "--threads", "-x", "-X", "-M", "--log", "--timeout",
    "--jitter", "--kdcHost", "--aesKey", "--gfail-limit", "--ufail-limit", "--fail-limit",
    "--exec-method", "--codec", "--spider", "--pattern", "--regex", "--content", "--depth",
    "--share", "--username", "--password", "--hash", "--domain", "--dc-ip", "--use-kcache",
    "--local-auth-file", "-id", "--cred-id", "--wmi-namespace", "--wmi", "-L", "--delegate",
}


def _nxc(args: list[str], t: Targets) -> None:
    pos = _positionals(args, _NXC_ARG)
    module_opts = False
    for i, a in enumerate(args):
        if a == "-o":
            module_opts = True
        elif a.startswith("-"):
            module_opts = False
        elif module_opts and i > 0:
            pos = [p for p in pos if p != a]
    if pos and pos[0] in ("smb", "ssh", "ldap", "winrm", "mssql", "rdp", "ftp", "wmi", "vnc", "nfs"):
        pos = pos[1:]
    for p in pos:
        if "=" in p:
            continue
        if _looks_like_file(p):
            t.add_file(p)
        elif _looks_like_target(p):
            t.add(p)
    for dc in _opt(args, "--dc-ip", "--kdcHost"):
        t.add(dc)


def _smbclient(args: list[str], t: Targets) -> None:
    for ip in _opt(args, "-I", "--ip-address"):
        t.add(ip)
    for v in _opt(args, "-L", "--list"):
        t.add(v.lstrip("\\/").replace("\\", "/").split("/", 1)[0])
    pos = _positionals(args, {"-U", "--user", "-W", "-p", "-I", "-m", "-n", "-s", "-A", "-D", "-O", "-R",
                              "-t", "-T", "--port", "-L", "-c", "-d", "--workgroup", "--authentication-file"})
    for p in pos:
        if p.startswith(("//", "\\\\")):
            host = p.lstrip("\\/").replace("\\", "/").split("/", 1)[0]
            t.add(host)
            break


def _evil_winrm(args: list[str], t: Targets) -> None:
    for v in _opt(args, "-i", "--ip"):
        t.add(v)


_HYDRA_ARG = {"-l", "-L", "-p", "-P", "-C", "-M", "-o", "-b", "-t", "-T", "-w", "-W", "-c", "-s", "-m",
              "-x", "-e", "-E"}


def _hydra(args: list[str], t: Targets) -> None:
    files = _opt(args, "-M")
    for f in files:
        t.add_file(f)
    pos = _positionals(args, _HYDRA_ARG)
    if files:
        return  # Ziele stehen in der Datei, das Positionsargument ist der Dienst
    if not pos:
        return
    first = pos[0]
    if "://" in first:
        t.add(first)
    elif _looks_like_target(first):
        t.add(first)


def _nikto(args: list[str], t: Targets) -> None:
    for v in _opt(args, "-h", "-host", "--host"):
        if _looks_like_file(v) and not _URLISH.fullmatch(v):
            t.add_file(v)
        else:
            t.add(v)


_IMPACKET = {
    "psexec", "smbexec", "wmiexec", "dcomexec", "atexec", "secretsdump", "GetNPUsers", "GetUserSPNs",
    "GetADUsers", "lookupsid", "samrdump", "rpcdump", "reg", "services", "mssqlclient", "getTGT",
    "getST", "addcomputer", "rbcd", "dacledit", "owneredit", "findDelegation", "smbclient",
    "changepasswd", "getPac", "Get-GPPPassword", "wmiquery", "netview", "ntlmrelayx", "mqtt_check",
    "rdp_check", "DumpNTLMInfo", "net",
}
_IMPACKET_ARG = {"-hashes", "-aesKey", "-dc-ip", "-target-ip", "-port", "-codec", "-service-name",
                 "-remote-binary-name", "-shell-type", "-com-version", "-object", "-share", "-file", "-db",
                 "-keytab", "-usersfile", "-outputfile", "-format", "-request-user", "-spn",
                 "-impersonate", "-computer-name", "-computer-pass", "-delegate-to", "-delegate-from",
                 "-action", "-principal", "-target", "-target-dn", "-rights", "-dc-host", "-t", "-tf",
                 "-smb2support", "-of", "-c", "-domain-sid", "-user-id", "-groups", "-extra-sid",
                 "-new-pass", "-newhashes", "-altservice", "-dc", "-sam", "-system", "-security", "-ntds",
                 "-bootkey", "-resumefile", "-history", "-pwd-last-set", "-user-status", "-ldapfilter"}


def _impacket(tool: str, args: list[str], t: Targets) -> None:
    dc = _opt(args, "-dc-ip", "-target-ip", "-dc-host", attached=False)
    for v in dc:
        t.add(v)
    if tool == "ntlmrelayx":
        for v in _opt(args, "-t", attached=False):
            t.add(v)
        for f in _opt(args, "-tf", attached=False):
            t.add_file(f)
        return
    pos = _positionals(args, _IMPACKET_ARG)
    if not pos or pos[0].upper() == "LOCAL":
        return
    first = pos[0]
    if "@" in first:
        t.add(first.rsplit("@", 1)[1])
    elif not dc and "/" in first:
        domain = first.split("/", 1)[0]
        if domain and "." in domain:
            t.add(domain)
    elif not dc and "/" not in first and _looks_like_target(first):
        t.add(first)


_PING_ARG = {"-c", "-i", "-I", "-s", "-t", "-W", "-w", "-p", "-Q", "-M", "-l", "-m", "-F", "-T", "-S",
             "-N", "-e"}


def _ping(args: list[str], t: Targets) -> None:
    for p in _positionals(args, _PING_ARG):
        if _looks_like_target(p):
            t.add(p)


_NC_ARG = {"-p", "-s", "-w", "-i", "-q", "-e", "-c", "-x", "-X", "-I", "-O", "-P", "-T", "-V", "-W",
           "--proxy", "--source", "--wait", "--exec", "--sh-exec", "--output"}


def _nc(args: list[str], t: Targets) -> None:
    def short_flag(f: str) -> bool:
        return any(a.startswith("-") and not a.startswith("--") and f in a[1:] for a in args
                   if a not in _NC_ARG)

    if short_flag("l") or "--listen" in args:
        return
    pos = _positionals(args, _NC_ARG)
    if pos and _looks_like_target(pos[0]):
        t.add(pos[0])


def _host_flag(*names: str) -> Callable[[list[str], Targets], None]:
    def run(args: list[str], t: Targets) -> None:
        for v in _opt(args, *names):
            if "://" in v:
                t.add(v)
            else:
                _add_host_list(t, v)
    return run


def _first_positional(with_arg: set[str]) -> Callable[[list[str], Targets], None]:
    def run(args: list[str], t: Targets) -> None:
        pos = _positionals(args, with_arg)
        if pos:
            target = _host_of_userhost(pos[0]) if "://" not in pos[0] else pos[0]
            if pos[0].startswith(("//", "\\\\")):
                target = pos[0].lstrip("\\/").replace("\\", "/").split("/", 1)[0]
            if _looks_like_target(target):
                t.add(target)
    return run


def _xfreerdp(args: list[str], t: Targets) -> None:
    for a in args:
        if a.startswith(("/v:", "-v:")):
            t.add(a[3:])


def _masscan(args: list[str], t: Targets) -> None:
    for f in _opt(args, "-iL", "--includefile"):
        t.add_file(f)
    for p in _positionals(args, {"-p", "--ports", "--rate", "-oX", "-oG", "-oJ", "-oL", "-iL", "-e",
                                 "--adapter-ip", "--router-mac", "--excludefile", "--exclude",
                                 "--includefile", "--source-ip", "--source-port", "--wait"}):
        if _looks_like_target(p):
            t.add(p)


_HANDLERS: dict[str, Callable[[list[str], Targets], None]] = {
    "nmap": _nmap,
    "ssh": _ssh,
    "curl": _curl,
    "wget": _wget,
    "gobuster": _url_positional,
    "ffuf": _url_tools,
    "feroxbuster": _url_tools,
    "wpscan": _url_tools,
    "sqlmap": _url_tools,
    "whatweb": _url_positional,
    "dirb": _url_positional,
    "nxc": _nxc,
    "netexec": _nxc,
    "crackmapexec": _nxc,
    "cme": _nxc,
    "evil-winrm": _evil_winrm,
    "hydra": _hydra,
    "nikto": _nikto,
    "ping": _ping,
    "ping6": _ping,
    "nc": _nc,
    "ncat": _nc,
    "netcat": _nc,
    "nc.traditional": _nc,
    "nc.openbsd": _nc,
    "smbmap": _host_flag("-H", "--host-file"),
    "rpcclient": _first_positional({"-U", "-W", "-c", "-p", "-I", "-s", "-d", "-A", "-n", "-O", "-R",
                                    "--user", "--workgroup", "--command", "--port"}),
    "enum4linux": _first_positional({"-u", "-p", "-w", "-k", "-s", "-r", "-d", "-K"}),
    "enum4linux-ng": _first_positional({"-u", "-p", "-w", "-t", "-oA", "-oJ", "-oY", "-d", "-K"}),
    "xfreerdp": _xfreerdp,
    "xfreerdp3": _xfreerdp,
    "masscan": _masscan,
    "rustscan": _host_flag("-a", "--addresses"),
    "ldapsearch": _host_flag("-H", "-h"),
    "telnet": _first_positional({"-l", "-n", "-b", "-e"}),
    "ftp": _first_positional({"-P"}),
    "mysql": _host_flag("-h", "--host"),
    "mariadb": _host_flag("-h", "--host"),
    "psql": _host_flag("-h", "--host"),
    "showmount": _first_positional(set()),
}


def analyze_targets(argv: Sequence[str]) -> Targets:
    """Ziele und Ziel-Listen eines Befehls (ohne Auflösung, ohne Dateizugriff)."""
    t = Targets()
    tool = tool_name(argv)
    if not tool:
        return t
    args = _rest(argv)
    stripped = strip_prefixes(list(argv))
    head = os.path.basename(stripped[0]) if stripped else ""
    impacket_style = head.startswith(("impacket-", "python")) or head.endswith(".py")
    if tool == "smbclient" and not impacket_style:
        _smbclient(args, t)
        return t
    if tool in _IMPACKET:
        _impacket(tool, args, t)
        return t
    handler = _HANDLERS.get(tool)
    if handler is not None:
        handler(args, t)
    return t


def extract_targets(argv: Sequence[str]) -> list[str]:
    """Rohe Ziele eines Befehls (siehe :func:`analyze_targets`)."""
    return analyze_targets(argv).targets
