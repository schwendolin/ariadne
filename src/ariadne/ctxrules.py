"""Regeln für den Kontext-Stapel eines Terminals (Architektur 3.5).

Nur Standardbibliothek. Wird vom Shim (Kopie des Stapels, Anzeige im Titel) und
von der Auswertung (Kontextspannen in Schicht 2) gleich verwendet, damit beide
dasselbe Ergebnis liefern.

Grundsätze:

* Unten liegt immer die lokale Stufe (Kali).
* Ein Session-Starter (ssh, evil-winrm, nc -l ...) legt eine Stufe mit
  unbekanntem Host an. Der Ziel-Kandidat aus argv bleibt unbestätigt.
* Nur gültige D-Marker (Nonce und Vordergrund geprüft) schliessen Stufen.
  Exit-Code 148 (Ctrl-Z) hält aktive Stufen nur an, ``fg`` holt sie zurück.
* Hosts sind eingegebene Kennungen, nie aufgelöste IDs.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field, replace

__all__ = [
    "Stage",
    "SessionStart",
    "PrivChange",
    "Resume",
    "Classification",
    "split_command",
    "command_argvs",
    "context_argv",
    "strip_prefixes",
    "classify",
    "ContextStack",
    "EXIT_SUSPENDED",
]

EXIT_SUSPENDED = 148  # 128 + SIGTSTP


@dataclass(frozen=True)
class Stage:
    """Kompatibel zu ``ariadne.events.Stage`` (gleiche Felder)."""

    kind: str
    host: str | None = None
    user: str | None = None
    opened_at: int = 0
    state: str = "active"  # active | suspended
    source: str = "auto"  # auto | hotkey | webui | cli | suggestion
    candidate: str | None = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, d: dict) -> Stage:
        allowed = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in allowed})


@dataclass(frozen=True)
class SessionStart:
    kind: str  # ssh | winrm | remote | revshell | msf | db
    candidate: str | None = None  # Ziel aus argv, unbestätigt
    user: str | None = None
    listener: bool = False


@dataclass(frozen=True)
class PrivChange:
    user: str = "root"


@dataclass(frozen=True)
class Resume:
    job: str | None = None


Classification = SessionStart | PrivChange | Resume | None


# --------------------------------------------------------------------------- #
# argv-Aufbereitung
# --------------------------------------------------------------------------- #


def split_command(cmd: str) -> list[str]:
    """Zerlegt eine Befehlszeile wie die Shell (ohne Expansion).

    Bei Pipelines und Listen zählt nur der erste einfache Befehl, denn nur der
    kann eine interaktive Sitzung im Vordergrund halten (``nc -lvnp 4444 | tee``
    ist trotzdem ein Listener).
    """
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        tokens = cmd.split()
    argv: list[str] = []
    for tok in tokens:
        if tok and set(tok) <= set(";&|()"):
            break
        if tok and set(tok) <= set("<>"):
            break
        argv.append(tok)
    return argv


def command_argvs(cmd: str) -> list[list[str]]:
    """Alle einfachen Befehle einer Zeile (``stty raw -echo; fg`` ergibt zwei).

    Umleitungsziele (``> datei``) gehören nicht zu argv.
    """
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        tokens = list(lex)
    except ValueError:
        return [cmd.split()] if cmd.split() else []
    out: list[list[str]] = [[]]
    redirect = False
    for tok in tokens:
        if tok and set(tok) <= set(";&|()"):
            out.append([])
            redirect = False
        elif tok and set(tok) <= set("<>"):
            redirect = True
        elif redirect:
            redirect = False
        else:
            out[-1].append(tok)
    return [c for c in out if c]


def context_argv(cmd: str) -> list[str]:
    """argv, das für den Kontext-Stapel zählt (``ContextStack.on_command_start``).

    Normalerweise der erste einfache Befehl (:func:`split_command`). Ergibt der
    keine Regel und ist ein späterer Befehl ``fg`` bzw. ``%n``, zählt dieser:
    beim Shell-Upgrade steht ``fg`` hinten (``stty raw -echo; fg``), sonst bliebe
    die angehaltene Remote-Stufe angehalten.
    """
    first = split_command(cmd)
    if classify(first) is None:
        for argv in command_argvs(cmd)[1:]:
            if isinstance(classify(argv), Resume):
                return argv
    return first


_PREFIX_WITH_ARG = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t"},
    "proxychains": {"-f"},
    "proxychains4": {"-f"},
    "rlwrap": {"-a", "-b", "-c", "-e", "-f", "-H", "-l", "-o", "-O", "-p", "-P", "-q", "-s",
               "-S", "-t", "-w", "-z"},
    "torsocks": {"-u", "-p", "-a", "-P"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e"},
    "nice": {"-n"},
    "env": {"-u", "-C", "-S"},
}
_PREFIX_PLAIN = {"time", "nohup", "command", "exec", "builtin", "noglob", "unbuffer"}


def strip_prefixes(argv: Sequence[str]) -> list[str]:
    """Entfernt Wrapper wie ``sudo``, ``proxychains4``, ``rlwrap``, ``env X=1``.

    ``sudo`` mit ``-i``/``-s`` (ohne Befehl) bleibt stehen, weil es selbst eine
    neue Shell öffnet.
    """
    args = list(argv)
    changed = True
    while args and changed:
        changed = False
        head = os.path.basename(args[0])
        if head in _PREFIX_PLAIN:
            args = args[1:]
            changed = True
            continue
        if head == "env":
            i = 1
            while i < len(args) and (args[i].startswith("-") or "=" in args[i]):
                i += 2 if args[i] in _PREFIX_WITH_ARG["env"] else 1
            args = args[i:]
            changed = True
            continue
        if "=" in args[0] and not args[0].startswith("-") and args[0].split("=", 1)[0].isidentifier():
            args = args[1:]  # VAR=wert befehl
            changed = True
            continue
        if head in _PREFIX_WITH_ARG:
            opts = _PREFIX_WITH_ARG[head]
            i = 1
            shell_flag = False
            while i < len(args) and args[i].startswith("-"):
                if head == "sudo" and args[i] in ("-i", "-s", "--login", "--shell"):
                    shell_flag = True
                if args[i] == "--":
                    i += 1
                    break
                i += 2 if args[i] in opts else 1
            if head == "timeout" and i < len(args):
                i += 1  # Dauer
            if head == "sudo" and shell_flag and i >= len(args):
                return list(args)  # sudo -i ohne Befehl: neue Root-Shell
            args = args[i:]
            changed = True
    return args


def _tool_name(argv: Sequence[str]) -> tuple[str, list[str]]:
    """Name des Tools und restliche Argumente; ``python3 psexec.py`` wird zu psexec."""
    if not argv:
        return "", []
    head = os.path.basename(argv[0])
    rest = list(argv[1:])
    if head.startswith("python") and rest and rest[0].endswith(".py"):
        head = os.path.basename(rest[0])
        rest = rest[1:]
    if head.endswith(".py"):
        head = head[:-3]
    if head.startswith("impacket-"):
        head = head[len("impacket-") :]
    return head, rest


def _positionals(args: Sequence[str], opts_with_arg: Iterable[str]) -> list[str]:
    opts = set(opts_with_arg)
    out: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(args[i + 1 :])
            break
        if a.startswith("-") and len(a) > 1:
            if a in opts:
                i += 2
                continue
            # zusammengezogene Kurzoptionen mit Argument am Ende (z. B. -p22)
            i += 1
            continue
        out.append(a)
        i += 1
    return out


def _opt_value(args: Sequence[str], *names: str) -> str | None:
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                return args[i + 1]
            if n.startswith("--") and a.startswith(n + "="):
                return a.split("=", 1)[1]
            if not n.startswith("--") and len(n) == 2 and a.startswith(n) and len(a) > 2:
                return a[2:]
    return None


def _has_flag(args: Sequence[str], *flags: str) -> bool:
    for a in args:
        if a in flags:
            return True
        if a.startswith("-") and not a.startswith("--"):
            for f in flags:
                if len(f) == 2 and f[0] == "-" and not f.startswith("--") and f[1] in a[1:]:
                    return True
    return False


def _split_userhost(s: str) -> tuple[str | None, str]:
    if "@" in s:
        user, host = s.rsplit("@", 1)
        return (user or None), host
    return None, s


def _impacket_target(s: str) -> tuple[str | None, str | None]:
    """``domain/user:pass@host`` -> (user, host). Passwort wird verworfen."""
    if "@" not in s:
        return None, s or None
    cred, host = s.rsplit("@", 1)
    user = cred.split("/", 1)[-1].split(":", 1)[0] or None
    return user, host or None


_SSH_OPTS_ARG = {"-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
                 "-o", "-p", "-Q", "-R", "-S", "-W", "-w", "-B", "-P"}
_IMPACKET_SHELLS = {"psexec", "smbexec", "wmiexec", "dcomexec"}
_IMPACKET_OPTS_ARG = {"-hashes", "-aesKey", "-dc-ip", "-target-ip", "-port", "-codec",
                      "-service-name", "-remote-binary-name", "-shell-type", "-com-version",
                      "-object", "-share", "-file", "-db", "-windows-auth", "-k", "-ts",
                      "-keytab", "-debug"}
_IMPACKET_FLAGS = {"-k", "-no-pass", "-ts", "-debug", "-windows-auth", "-silentcommand", "-nooutput"}


def classify(argv: Sequence[str]) -> Classification:
    """Ordnet einen Befehl ein: Session-Start, Rechtewechsel, ``fg`` oder nichts.

    Konservativ: Im Zweifel ``None``. Ein falscher Session-Start ist schlimmer
    als ein verpasster, denn verpasste lassen sich per Hotkey nachtragen.
    """
    args = strip_prefixes(argv)
    if not args:
        return None
    head = os.path.basename(args[0])

    # Rechtewechsel auf dem lokalen Host
    if head == "sudo":  # nur noch hier, wenn -i/-s ohne Befehl
        user = _opt_value(args[1:], "-u") or "root"
        return PrivChange(user)
    if head == "su":
        rest = [a for a in args[1:] if a not in ("-", "-l", "--login", "-p", "-m")]
        if _has_flag(args[1:], "-c") or "--command" in args:
            return None
        return PrivChange(rest[0] if rest else "root")
    if head in ("fg",) or (head.startswith("%") and len(argv) == 1):
        job = args[1] if head == "fg" and len(args) > 1 else (head if head.startswith("%") else None)
        return Resume(job)
    if os.path.basename(argv[0]) == "sudo" and head in ("su", "bash", "zsh", "sh", "fish", "dash"):
        return PrivChange("root")

    tool, rest = _tool_name(args)

    if tool == "ssh":
        if _has_flag(rest, "-N", "-V", "-G", "-Q", "-O", "-f"):
            return None
        pos = _positionals(rest, _SSH_OPTS_ARG)
        if not pos or len(pos) > 1:  # kein Ziel oder Remote-Befehl
            return None
        user, host = _split_userhost(pos[0])
        user = _opt_value(rest, "-l") or user
        return SessionStart("ssh", host, user)

    if tool == "evil-winrm":
        host = _opt_value(rest, "-i", "--ip")
        user = _opt_value(rest, "-u", "--user")
        return SessionStart("winrm", host, user)

    if tool in ("nc", "ncat", "netcat", "nc.traditional", "nc.openbsd"):
        if _has_flag(rest, "-l") or "--listen" in rest:
            return SessionStart("revshell", None, None, listener=True)
        if _has_flag(rest, "-z") or "--zero" in rest:
            return None  # Portscan
        pos = _positionals(rest, {"-p", "-s", "-w", "-i", "-q", "-e", "-c", "-x", "-X", "-I", "-O"})
        if len(pos) >= 2:
            return SessionStart("revshell", pos[0], None)  # Bind-Shell
        return None

    if tool == "socat":
        joined = " ".join(rest).upper()
        if "LISTEN" in joined or "TCP-L:" in joined:
            return SessionStart("revshell", None, None, listener=True)
        return None

    if tool in ("pwncat-cs", "pwncat"):
        listener = _has_flag(rest, "-l") or "--listen" in rest or _has_flag(rest, "-lp")
        pos = _positionals(rest, {"-p", "--port", "-m", "--platform", "-c", "--config", "-i",
                                  "--identity", "-r", "--download-plugins"})
        host = None if listener or not pos else _split_userhost(pos[0])[1]
        return SessionStart("revshell", host, None, listener=listener)

    if tool == "msfconsole":
        x = _opt_value(rest, "-x", "--execute-command")
        if x and x.rstrip().rstrip(";").rstrip().endswith("exit"):
            return None
        return SessionStart("msf")

    if tool in ("mysql", "mariadb"):
        if _has_flag(rest, "-e") or any(a.startswith("--execute") for a in rest):
            return None
        return SessionStart("db", _opt_value(rest, "-h", "--host"), _opt_value(rest, "-u", "--user"))

    if tool == "psql":
        if _has_flag(rest, "-c", "-f", "-l") or any(a.startswith(("--command", "--file", "--list"))
                                                    for a in rest):
            return None
        return SessionStart("db", _opt_value(rest, "-h", "--host"), _opt_value(rest, "-U", "--username"))

    if tool == "mssqlclient":
        pos = _positionals(rest, _IMPACKET_OPTS_ARG - _IMPACKET_FLAGS)
        if not pos:
            return None
        if _opt_value(rest, "-file"):
            return None
        user, host = _impacket_target(pos[0])
        return SessionStart("db", host, user)

    if tool in _IMPACKET_SHELLS:
        pos = _positionals(rest, _IMPACKET_OPTS_ARG - _IMPACKET_FLAGS)
        if not pos or len(pos) > 1:  # mit Befehl: nicht interaktiv
            return None
        user, host = _impacket_target(pos[0])
        return SessionStart("remote", host, user)

    if tool == "smbclient":
        if _has_flag(rest, "-L", "-c") or any(a.startswith(("--list", "--command")) for a in rest):
            return None
        pos = _positionals(rest, {"-U", "--user", "-W", "-p", "-I", "-m", "-n", "-s", "-A", "-D",
                                  "-O", "-R", "-t", "-T", "--port"})
        if not pos:
            return None
        host = pos[0].lstrip("\\/").replace("\\", "/").split("/", 1)[0] or None
        user = _opt_value(rest, "-U", "--user")
        if user and "%" in user:
            user = user.split("%", 1)[0]
        return SessionStart("remote", host, user)

    if tool in ("telnet", "ftp", "lftp", "rlogin"):
        pos = _positionals(rest, {"-l", "-u", "-p", "-e", "-n"})
        if not pos:
            return None
        user, host = _split_userhost(pos[0])
        return SessionStart("remote", host, _opt_value(rest, "-l") or user)

    return None


# --------------------------------------------------------------------------- #
# Stapel
# --------------------------------------------------------------------------- #


@dataclass
class ContextStack:
    """Kontext-Stapel eines Terminals. ``stages[0]`` ist immer lokal (Kali).

    ``jobs`` führt die angehaltenen Jobs in der Reihenfolge des Anhaltens, je mit
    den ``opened_at`` der Stufen, die sie angehalten haben; ein Programm ohne Stufe
    (vim, less) ist ein leerer Platzhalter. ``fg`` holt so den Job zurück, den
    auch die Shell fortsetzt. ``None`` heisst unbekannt (nach einem Schnappschuss
    mit angehaltenen Stufen): dann gilt die jüngste angehaltene Stufe.
    """

    stages: list[Stage] = field(default_factory=lambda: [Stage(kind="local", host="local")])
    jobs: list[tuple[int, ...]] | None = field(default_factory=list, compare=False)

    # ---- Abfragen -------------------------------------------------------- #

    def top(self) -> Stage:
        for st in reversed(self.stages):
            if st.state == "active":
                return st
        return self.stages[0]

    def is_local(self) -> bool:
        return self.top().kind in ("local", "su")

    def snapshot(self) -> list[dict]:
        return [s.to_dict() for s in self.stages]

    @classmethod
    def from_snapshot(cls, data: Iterable[dict]) -> ContextStack:
        stages = [Stage.from_dict(d) for d in data]
        if not stages or stages[0].kind != "local":
            stages.insert(0, Stage(kind="local", host="local"))
        jobs: list[tuple[int, ...]] | None = None if any(s.state == "suspended" for s in stages) else []
        return cls(stages, jobs)

    # ---- automatische Übergänge aus Markern ------------------------------ #

    def on_command_start(self, argv: Sequence[str], offset: int) -> Classification:
        """C-Marker (gültig): wendet die argv-Regel an und gibt sie zurück."""
        c = classify(argv)
        if isinstance(c, SessionStart):
            self.stages.append(
                Stage(kind=c.kind, host=None, user=c.user, opened_at=offset, source="auto",
                      candidate=c.candidate)
            )
        elif isinstance(c, PrivChange):
            self.stages.append(
                Stage(kind="su", host="local", user=c.user, opened_at=offset, source="auto")
            )
        elif isinstance(c, Resume):
            self._resume(c.job)
        return c

    def _resume(self, job: str | None) -> None:
        if self.jobs is None:  # Reihenfolge unbekannt: jüngste angehaltene Stufe
            for i in range(len(self.stages) - 1, 0, -1):
                if self.stages[i].state == "suspended":
                    self.stages[i] = replace(self.stages[i], state="active")
                    break
            return
        n = len(self.jobs)
        spec = "%" if job is None else job
        spec = spec[1:] if spec.startswith("%") else spec
        if spec in ("", "%", "+"):
            idx = n - 1
        elif spec == "-":
            idx = n - 2
        elif spec.isdigit():
            idx = int(spec) - 1  # Jobnummer der Shell, sofern keine Hintergrundjobs dazwischen
        else:
            return  # %name, %?text: unklar, keine Stufe aktivieren
        if not 0 <= idx < n:
            return
        offs = set(self.jobs.pop(idx))
        for i in range(1, len(self.stages)):
            st = self.stages[i]
            if st.state == "suspended" and st.opened_at in offs:
                self.stages[i] = replace(st, state="active")

    def on_command_end(self, exit_code: int | None, offset: int) -> None:
        """D-Marker (gültig, Vordergrund geprüft)."""
        if exit_code == EXIT_SUSPENDED:
            held = tuple(s.opened_at for s in self.stages[1:] if s.state == "active")
            self.stages = [self.stages[0]] + [
                replace(s, state="suspended") if s.state == "active" else s
                for s in self.stages[1:]
            ]
            if self.jobs is not None:
                self.jobs.append(held)  # leer: Programm ohne Stufe (Platzhalter)
            return
        # Die Vordergrund-Sitzung ist beendet: aktive Stufen schliessen,
        # angehaltene bleiben (andere Jobs).
        self.stages = [self.stages[0]] + [s for s in self.stages[1:] if s.state == "suspended"]

    # ---- Nutzerentscheide ------------------------------------------------ #

    def set_top(self, *, host: str | None = None, user: str | None = None,
                kind: str | None = None, source: str = "hotkey", offset: int = 0) -> None:
        """Host/Benutzer der obersten aktiven Stufe setzen. Auf der lokalen Basis
        wird stattdessen eine neue Stufe ab ``offset`` angelegt (Sprung ohne
        erkannten Start; der Segmenter nimmt dafür ``from_off`` des Entscheids)."""
        idx = self._top_index()
        if idx == 0:
            self.push(kind=kind or "unknown", host=host, user=user, offset=offset, source=source)
            return
        st = self.stages[idx]
        self.stages[idx] = replace(
            st,
            host=host if host is not None else st.host,
            user=user if user is not None else st.user,
            kind=kind or st.kind,
            source=source,
        )

    def push(self, *, kind: str = "unknown", host: str | None = None, user: str | None = None,
             offset: int = 0, source: str = "hotkey") -> None:
        self.stages.append(Stage(kind=kind, host=host, user=user, opened_at=offset, source=source))

    def pop(self) -> Stage | None:
        idx = self._top_index()
        if idx == 0:
            return None
        return self.stages.pop(idx)

    def _top_index(self) -> int:
        for i in range(len(self.stages) - 1, -1, -1):
            if self.stages[i].state == "active":
                return i
        return 0

    # ---- Anzeige --------------------------------------------------------- #

    def label(self) -> str:
        """Kurzform für Titel und Brotkrumen, z. B. ``web01 root`` oder ``? ssh``.

        Achtung: Das Ergebnis enthält Nutzereingaben und muss vor der Ausgabe
        ins Terminal durch ``ariadne.termsafe.term_safe`` laufen.
        """
        st = self.top()
        if st.kind == "local":
            return "kali"
        if st.kind == "su":
            return f"kali {st.user or 'root'}"
        host = st.host or "?"
        if host.startswith(("ip:", "name:")):
            host = host.split("/", 1)[-1] if host.startswith("ip:") else host[5:]
        return f"{host} {st.user}" if st.user else f"{host} {st.kind}"
