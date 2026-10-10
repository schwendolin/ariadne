"""Parser ``listener.callback``: Rückverbindungen auf lokalen Listenern (Architektur 5.6).

``ariadne.ctxrules`` legt beim C-Marker eines Listeners (``nc -lvnp``,
``pwncat-cs -lp``, ``msfconsole``) sofort eine Stufe an. Die Meldung steht
deshalb in einer Einheit vom Typ ``segment`` mit ``context.kind`` ``revshell``
(bzw. ``msf``/``meterpreter``) oder in einer Befehls-Einheit des Listeners.

Formate: nc traditional (``connect to [A] from (UNKNOWN) [B] P``), ncat
(``Ncat: Connection from B:P.``), nc.openbsd (``Connection received on B P``),
pwncat (``received connection from B:P``) und Metasploit
(``[*] Command shell session N opened (A:LP -> B:P)``, ``Meterpreter session``).

Ein Ziel kann solche Zeilen selbst ausgeben. Deshalb wird nur der erste Treffer
Beobachtung ``access.callback`` (Subjekt ``Ref.ip(B)``); weitere Treffer sind
Mentions vom Typ ``callback``. Bei nc-artigen Listenern zählt der erste Treffer
zudem nur, wenn davor ausschliesslich Statuszeilen des Listeners stehen (sonst
war die echte Meldung nicht in der Aufnahme, und der Treffer kann vom Ziel sein).
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import ClassVar

from ariadne.parsers._common import canon_ip, suspect_attrs, text_lines, tool_argv
from ariadne.parsers.api import Mention, Obs, Ref, Span, Trust, UnitView
from ariadne.parsers.safe import rx

__all__ = ["ListenerCallbackParser"]

_NC_TOOLS = {"nc", "ncat", "netcat", "nc.traditional", "nc.openbsd", "socat"}
_PWNCAT = {"pwncat-cs", "pwncat"}
_CTX_KINDS = {"revshell", "msf", "meterpreter"}

# (Listener, Muster, Gruppen: lokal, remote-host, remote-port)
_CALLBACKS: tuple[tuple[str, str], ...] = (
    ("nc", r"^connect to \[([^\]\s]{1,64})\] from [^\[\]]{0,256}\[([^\]\s]{1,64})\] ([0-9]{1,5})\s*$"),
    ("ncat", r"^Ncat: Connection from ([0-9A-Fa-f.:]{2,64}?)(?::([0-9]{1,5}))?\.?\s*$"),
    ("nc", r"^Connection received on (\S{1,253}) ([0-9]{1,5})\s*$"),
    ("pwncat", r"received connection from ([0-9A-Fa-f.:]{2,64}):([0-9]{1,5})"),
    ("msf", r"^\[\*\] (?:Command shell|Meterpreter) session ([0-9]{1,6}) opened \(([^\s()]{1,80}) -> "
            r"([^\s()]{1,80})\)"),
)
_LISTENING: tuple[str, ...] = (
    r"^listening on \[[^\]]*\] ([0-9]{1,5})",
    r"^Ncat: Listening on \S*?:([0-9]{1,5})\s*$",
    r"^Listening on \S+ ([0-9]{1,5})\s*$",
    r"bound to \S*?:([0-9]{1,5})",
    r"^\[\*\] Started (?:reverse|bind) \S+ handler on \S*?:([0-9]{1,5})",
)
_STATUS_PREFIXES = (
    "listening on ", "Listening on ", "Ncat: ", "Warning: ", "UDP listen", "bound to ",
    "Connection from ",
)


def _split_hostport(s: str) -> tuple[str | None, str | None]:
    """``10.0.0.1:4444`` bzw. ``[::1]:4444`` bzw. ``::1:4444`` -> (Adresse, Port)."""
    s = s.strip()
    if s.startswith("[") and "]" in s:
        host, _, rest = s[1:].partition("]")
        return canon_ip(host), rest.lstrip(":") or None
    if ":" in s:
        host, _, port = s.rpartition(":")
        if port.isdigit():
            return canon_ip(host), port
    return canon_ip(s), None


def _argv_port(rest: Sequence[str]) -> str | None:
    for k, a in enumerate(rest):
        if a in ("-p", "--port", "-lp", "-lvnp", "-nlvp", "-lnvp", "-vlnp", "-nvlp") and k + 1 < len(rest):
            if rest[k + 1].isdigit():
                return rest[k + 1]
        if a.startswith("--port="):
            v = a.split("=", 1)[1]
            if v.isdigit():
                return v
    for a in reversed(rest):
        if a.isdigit() and 0 < int(a) <= 65535:
            return a
        if ":" in a and a.rsplit(":", 1)[1].isdigit() and "LISTEN" in a.upper():
            return a.rsplit(":", 1)[1]
    return None


class ListenerCallbackParser:
    id: ClassVar[str] = "listener.callback"
    version: ClassVar[str] = "1"
    trust: ClassVar[Trust] = "tool_text"
    auto_eligible: ClassVar[bool] = False

    def match(self, unit: UnitView) -> int:
        ctx = unit.context or {}
        if unit.kind == "segment" and ctx.get("kind") in _CTX_KINDS:
            return 40
        if unit.kind in ("command", "segment"):
            tool, _ = tool_argv(unit.argv)
            if tool in _NC_TOOLS or tool in _PWNCAT or tool == "msfconsole":
                return 40
        return 0

    def companions(self, argv: Sequence[str], cwd: str) -> list[str]:
        return []

    def parse(self, unit: UnitView) -> Iterator[Obs | Mention]:
        tool, rest = tool_argv(unit.argv)
        lport = _argv_port(rest) if tool in _NC_TOOLS or tool in _PWNCAT else None
        first_done = False
        only_status = True  # bisher nur Statuszeilen des Listeners
        for i, line, text in text_lines(unit):
            stripped = text.strip()
            lm = None
            for pat in _LISTENING:
                lm = rx(pat).search(text)
                if lm is not None:
                    if not first_done:
                        lport = lm.group(1)
                    break
            hit = self._match(text)
            if hit is None:
                if stripped and not stripped.startswith(_STATUS_PREFIXES) and lm is None:
                    only_status = False
                continue
            listener, local, rhost, rport, session, (a, b) = hit
            if tool in _PWNCAT:
                listener = "pwncat"
            port = lport
            if listener == "msf" and local:
                port = _split_hostport(local)[1] or port
            remote = f"{rhost}:{rport}" if rport else rhost
            attrs = {"listener": listener, "remote": remote, **suspect_attrs(line)}
            if local:
                attrs["local"] = local if (listener == "msf" or not port) else f"{local}:{port}"
            if session:
                attrs["session"] = session
            span = Span(i, i, a, b)
            ip = canon_ip(rhost)
            trusted = listener in ("msf", "pwncat") or only_status
            if not first_done and ip is not None and trusted:
                first_done = True
                value = f"{listener}:{port}" if port else listener
                yield Obs(Ref.ip(ip), "access.callback", value, span, attrs=attrs)
                continue
            first_done = True
            reason = "not_first" if trusted else "after_output"
            yield Mention("callback", remote, span, {**attrs, "reason": reason})

    @staticmethod
    def _match(text: str) -> tuple[str, str | None, str, str | None, str | None, tuple[int, int]] | None:
        for listener, pat in _CALLBACKS:
            m = rx(pat).search(text)
            if m is None:
                continue
            if listener == "msf":
                local, remote = m.group(2), m.group(3)
                rhost, rport = _split_hostport(remote)
                if rhost is None:
                    return None
                return "msf", local, rhost, rport, m.group(1), m.span()
            if listener == "pwncat":
                return "pwncat", None, m.group(1), m.group(2), None, m.span()
            if pat.startswith("^connect to"):
                return "nc", m.group(1), m.group(2), m.group(3), None, m.span()
            if pat.startswith("^Ncat"):
                return "ncat", None, m.group(1), m.group(2), None, m.span()
            return "nc", None, m.group(1), m.group(2), None, m.span()
        return None
