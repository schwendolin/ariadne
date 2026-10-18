"""Phasen der Befehle für das Writeup (E62, Architektur 8.7).

Regeln schlagen für jeden Befehl eine Phase der Vorlage vor (``nmap`` zu Scanning, Listener und
Exploits zu Exploitation, ``linpeas`` zu Post-Exploitation). Der Mensch korrigiert per Entscheid
``d.unit.phase`` (``cmd_id``, ``template``, ``phase``). Der jüngste nicht widerrufene Entscheid je
Vorlage und Befehl gilt. Weil Entscheide im Journal stehen und die Projektion sie in der Tabelle
``decision`` hält, übersteht die Korrektur jeden Reparse; eine eigene Tabelle braucht es nicht.

Nur reine Funktionen: Sie lesen ``unit`` und ``decision`` und schreiben nichts. Zieldaten (der
Befehlstext) werden nur verglichen, nie ausgeführt und nie aufgelöst (E10).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

__all__ = [
    "TEMPLATES",
    "PHASES",
    "PHASE_LABELS",
    "OMIT",
    "valid_phase",
    "program_of",
    "suggest",
    "overrides",
    "assign",
]

TEMPLATES = ("cys", "htb")
OMIT = "omit"

PHASES: dict[str, tuple[str, ...]] = {
    "cys": ("recon", "scanning", "exploitation", "post", "reporting"),
    "htb": ("enumeration", "foothold", "privesc", "pivot", "loot", "lessons"),
}

PHASE_LABELS: dict[str, str] = {
    "recon": "Reconnaissance",
    "scanning": "Scanning und Enumeration",
    "exploitation": "Exploitation",
    "post": "Post-Exploitation",
    "reporting": "Reporting",
    "enumeration": "Enumeration",
    "foothold": "Foothold",
    "privesc": "Privilege Escalation",
    "pivot": "Pivot",
    "loot": "Loot",
    "lessons": "Lessons Learned",
    OMIT: "Nicht im Writeup",
}


def valid_phase(template: str, phase: str) -> bool:
    return template in PHASES and (phase in PHASES[template] or phase == OMIT)


# Programme, die nur einen anderen Befehl starten; der eigentliche Befehl folgt danach.
_WRAPPERS = frozenset(
    {
        "sudo",
        "doas",
        "proxychains",
        "proxychains4",
        "env",
        "time",
        "nohup",
        "stdbuf",
        "unbuffer",
        "timeout",
        "torsocks",
        "rlwrap",
        "exec",
        "command",
        "builtin",
        "nice",
        "ionice",
        "faketime",
    }
)
_INTERPRETERS = frozenset(
    {"python", "python2", "python3", "perl", "ruby", "bash", "sh", "zsh", "php", "node"}
)

# Werkzeug -> (Phase cys, Phase htb)
_TOOLS: dict[str, tuple[str, str]] = {}


def _add(names: str, cys: str, htb: str) -> None:
    for n in names.split():
        _TOOLS[n] = (cys, htb)


_add(
    "whois dig nslookup host theharvester theHarvester amass subfinder dnsrecon dnsenum fierce "
    "recon-ng shodan netdiscover arp-scan fping traceroute tracepath ping ping6 sublist3r",
    "recon",
    "enumeration",
)
_add(
    "nmap masscan rustscan unicornscan naabu nikto gobuster ffuf feroxbuster dirb dirsearch wfuzz "
    "whatweb wpscan joomscan droopescan sslscan sslyze testssl testssl.sh enum4linux enum4linux-ng "
    "smbmap smbclient nbtscan rpcclient snmpwalk snmp-check onesixtyone showmount ldapsearch "
    "nuclei curl wget httpx dnsx kerbrute rpcinfo nc-zv smtp-user-enum finger ike-scan "
    "sqsh mysql psql redis-cli ftp telnet tftp ncrack-scan",
    "scanning",
    "enumeration",
)
_add(
    "msfconsole msfvenom searchsploit hydra medusa ncrack patator sqlmap commix xsser "
    "crackmapexec netexec nxc evil-winrm psexec.py wmiexec.py smbexec.py impacket-psexec "
    "impacket-wmiexec impacket-smbexec responder ntlmrelayx.py impacket-ntlmrelayx "
    "pwncat pwncat-cs socat",
    "exploitation",
    "foothold",
)
_add(
    "linpeas linpeas.sh winpeas winpeas.exe winPEASx64.exe pspy pspy64 pspy32 linenum linenum.sh "
    "linux-exploit-suggester linux-exploit-suggester.sh les.sh getcap sudo-l lse.sh "
    "linux-smart-enumeration powerup.ps1 seatbelt",
    "post",
    "privesc",
)
_add("chisel ligolo ligolo-ng sshuttle plink plink.exe autossh", "post", "pivot")
_add(
    "mimikatz secretsdump.py impacket-secretsdump hashdump john hashcat unshadow pypykatz lazagne",
    "post",
    "loot",
)

_LISTENER_FLAGS = re.compile(r"^-[a-zA-Z]*l[a-zA-Z]*$")
_LOOT_PATHS = ("/etc/shadow", "root.txt", "user.txt", "flag", "id_rsa", ".kdbx", "ntds.dit", "sam")
_PRIVESC_HINTS = ("sudo -l", "find / -perm", "-perm -4000", "-perm -u=s", "getcap -r", "/etc/sudoers")
_LOCAL_HOSTS = (None, "", "local")


def _base(arg: str) -> str:
    return os.path.basename(arg.strip())


def program_of(argv: Sequence[Any]) -> tuple[str | None, list[str]]:
    """Name des eigentlichen Programms und seine Argumente (ohne sudo, proxychains, timeout ...)."""
    args = [str(a) for a in argv if isinstance(a, str | int)]
    i = 0
    while i < len(args):
        name = _base(args[i])
        if name in _WRAPPERS:
            i += 1
            # Optionen und Zahlen des Wrappers überspringen (sudo -u root, timeout 10)
            while i < len(args) and (args[i].startswith("-") or args[i].isdigit() or "=" in args[i]):
                if name in ("sudo", "doas") and args[i] in ("-u", "-g", "-C", "-p"):
                    i += 1  # Option mit Wert
                i += 1
            continue
        if name in _INTERPRETERS:
            j = i + 1
            while j < len(args) and args[j].startswith("-"):
                j += 1
            if j < len(args):
                return _base(args[j]), args[j + 1 :]
            return name, []
        return name, args[i + 1 :]
    return None, []


def _remote(context: Mapping[str, Any] | None) -> bool:
    ctx = context or {}
    host = ctx.get("host")
    kind = ctx.get("kind")
    return (host not in _LOCAL_HOSTS) or kind in ("ssh", "revshell", "msf", "meterpreter", "remote")


def suggest(
    template: str, argv: Sequence[Any], cmd_text: str | None, context: Mapping[str, Any] | None
) -> str | None:
    """Vorschlag der Regeln für einen Befehl, ``None`` wenn keine Regel passt."""
    if template not in PHASES:
        return None
    prog, rest = program_of(argv)
    text = (cmd_text or "").lower()
    remote = _remote(context)
    idx = 0 if template == "cys" else 1
    if prog is None:
        return None
    low = prog.lower()
    if low in ("ariadne", "clear", "ls", "cd", "pwd", "history", "exit", "reset"):
        return None
    if low in ("nc", "ncat", "netcat", "nc.traditional", "nc.openbsd"):
        if any(_LISTENER_FLAGS.match(a) for a in rest):
            return ("exploitation", "foothold")[idx]
        return ("scanning", "enumeration")[idx]
    if low in ("ssh", "scp"):
        if any(a in ("-L", "-R", "-D") or a.startswith(("-L", "-R", "-D")) for a in rest):
            return ("post", "pivot")[idx]
        return ("post", "privesc")[idx] if remote else ("exploitation", "foothold")[idx]
    hit = _TOOLS.get(prog) or _TOOLS.get(low)
    if hit is None and "exploit" in low:
        hit = ("exploitation", "foothold") if not remote else ("post", "privesc")
    if hit is not None:
        phase = hit[idx]
        if template == "htb" and phase == "enumeration" and remote:
            phase = "privesc"
        return phase
    # Ohne Werkzeug aus der Liste: Hinweise aus dem Befehl und dem Kontext
    if any(p in text for p in _LOOT_PATHS) and low in (
        "cat",
        "type",
        "more",
        "less",
        "head",
        "tail",
        "strings",
    ):
        return ("post", "loot")[idx]
    if any(h in text for h in _PRIVESC_HINTS):
        return ("post", "privesc")[idx]
    if remote:
        return ("post", "privesc")[idx]
    return None


def _json(text: Any, default: Any) -> Any:
    if not isinstance(text, str):
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def overrides(conn: Any, template: str, revoked: Iterable[str] = ()) -> dict[str, tuple[str, str]]:
    """``cmd_id`` -> (Phase, ``decision_id``) aus den aktiven ``d.unit.phase`` dieser Vorlage."""
    gone = set(revoked)
    out: dict[str, tuple[str, str]] = {}
    for did, payload in conn.execute(
        "SELECT id, payload_json FROM decision WHERE kind = 'd.unit.phase' ORDER BY seq"
    ):
        if did in gone:
            continue
        p = _json(payload, {}) or {}
        cid, tpl, phase = p.get("cmd_id"), p.get("template"), p.get("phase")
        if tpl != template or not isinstance(cid, str) or not isinstance(phase, str):
            continue
        if valid_phase(template, phase):
            out[cid] = (phase, str(did))
    return out


def assign(conn: Any, template: str, revoked: Iterable[str] = (), limit: int = 5000) -> list[dict[str, Any]]:
    """Alle Befehle mit Phase (``phase``, ``source``: ``decision``, ``rule`` oder ``none``), nach Zeit.

    Ein Befehl erscheint einmal (erste Einheit seiner ``cmd_id``)."""
    over = overrides(conn, template, revoked)
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for unit_id, cmd_id, argv, cmd_text, context, ts in conn.execute(
        "SELECT unit_id, cmd_id, argv, cmd_text, context, ts_utc_ns FROM unit "
        "WHERE kind = 'command' AND cmd_id IS NOT NULL ORDER BY ts_utc_ns, event_seq LIMIT ?",
        (int(limit),),
    ):
        if cmd_id in seen:
            continue
        seen.add(str(cmd_id))
        ctx = _json(context, {}) or {}
        decided = over.get(str(cmd_id))
        if decided is not None:
            phase, source, did = decided[0], "decision", decided[1]
        else:
            phase = suggest(template, _json(argv, []) or [], cmd_text, ctx)
            source, did = ("rule" if phase else "none"), None
        out.append(
            {
                "unit_id": unit_id,
                "cmd_id": cmd_id,
                "cmd_text": cmd_text,
                "ts": ts,
                "context": ctx,
                "phase": phase,
                "source": source,
                "decision_id": did,
                "program": program_of(_json(argv, []) or [])[0],
            }
        )
    return out
