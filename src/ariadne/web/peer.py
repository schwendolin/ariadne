"""Wer steckt hinter einer TCP-Verbindung auf Loopback? (Konzept Fernzugriff R2, Vertrag 3.4)

Nur Linux, nur ``/proc``, ohne root:

* :func:`find_socket` sucht den Client-Socket einer Verbindung gezielt über Netlink
  ``sock_diag`` (:func:`diag_lookup`, eine Abfrage mit dem 4-Tupel, etwa 15 µs, ohne root) und nur,
  wenn Netlink fehlt, in ``/proc/net/tcp`` und ``/proc/net/tcp6`` (lokale Adresse = Client,
  entfernte = Server; IPv4-mapped-Adressen gelten als IPv4). Ergebnis: UID und Inode. Die gezielte
  Suche hält eine Verbindungsflut eines fremden Benutzers billig (Befund SEC-W2: das Parsen der
  ganzen Tabelle wuchs mit jeder TIME_WAIT-Zeile).
* :func:`find_holders` sucht den Inode in ``/proc/<pid>/fd`` der Prozesse mit derselben UID.
  Nicht lesbare Prozesse (nicht «dumpable», z. B. ``sshd-session`` nach dem Rechtewechsel)
  werden übersprungen; findet sich kein Halter, ist der Peer «nicht lesbar» (leeres Tupel).
* :func:`resolve_peer` verbindet beides zum :class:`PeerInfo` einer Verbindung.
* :func:`proc_info`, :func:`same_process` und :func:`sshd_ancestor` lesen ``/proc/<pid>/stat``
  und ``status`` (auch bei nicht «dumpable» Prozessen lesbar): PID, PPID, Startzeit, ``comm``.

Alle Funktionen nehmen ``proc_root`` für Tests mit nachgebauten ``/proc``-Bäumen. Die Suche
in den fd-Tabellen kann bei vielen offenen Dateien einige Millisekunden kosten; der Server ruft
sie darum nur einmal pro Verbindung und nie im Loop des Daemons auf.
"""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import socket
import struct
import sys
from dataclasses import dataclass

__all__ = [
    "TcpEntry",
    "PeerInfo",
    "ProcInfo",
    "parse_proc_net",
    "find_socket",
    "diag_lookup",
    "DiagUnavailable",
    "find_holders",
    "resolve_peer",
    "proc_info",
    "proc_uid",
    "same_process",
    "sshd_ancestor",
    "SSHD_COMMS",
    "PASS_THROUGH",
]

PROC = "/proc"
SSHD_COMMS = frozenset({"sshd", "sshd-session"})
# Zwischen dem sshd-Prozess und ``ariadne remote serve`` dürfen nur Shells oder Python liegen.
PASS_THROUGH = frozenset({"sh", "bash", "zsh", "dash"})
MAX_ANCESTOR_STEPS = 4
_ESTABLISHED = 0x01
_HEX = re.compile(r"\A[0-9A-Fa-f]+\Z")


@dataclass(frozen=True)
class TcpEntry:
    local: tuple[str, int]
    remote: tuple[str, int]
    state: int
    uid: int
    inode: int


@dataclass(frozen=True)
class PeerInfo:
    """Peer einer Verbindung. ``pids`` leer heisst «nicht lesbar» (kein Halter mit lesbarer
    fd-Tabelle gefunden); sonst die PIDs aller Prozesse, die den Client-Socket halten."""

    uid: int
    inode: int
    pids: tuple[int, ...]

    @property
    def readable(self) -> bool:
        return bool(self.pids)


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    ppid: int
    start: int  # Startzeit in Clock-Ticks seit dem Boot (stat Feld 22)
    comm: str


# --------------------------------------------------------------------------- #
# /proc/net/tcp
# --------------------------------------------------------------------------- #


def _norm_ip(host: str) -> str:
    """Kanonische Form; IPv4-mapped IPv6 (``::ffff:127.0.0.1``) wird zu IPv4."""
    addr = ipaddress.ip_address(host.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return str(addr.ipv4_mapped)
    return str(addr)


def _decode_addr(text: str, byteorder: str) -> tuple[str, int]:
    host_hex, _, port_hex = text.partition(":")
    if not port_hex or not _HEX.match(host_hex) or not _HEX.match(port_hex):
        raise ValueError("Adresse unlesbar")
    fmt = "<I" if byteorder == "little" else ">I"
    if len(host_hex) == 8:
        raw = struct.pack(fmt, int(host_hex, 16))
    elif len(host_hex) == 32:
        raw = b"".join(struct.pack(fmt, int(host_hex[i:i + 8], 16)) for i in range(0, 32, 8))
    else:
        raise ValueError("Adresse unlesbar")
    return _norm_ip(str(ipaddress.ip_address(raw))), int(port_hex, 16)


def parse_proc_net(text: str, *, byteorder: str = sys.byteorder) -> list[TcpEntry]:
    """Zeilen aus ``/proc/net/tcp`` bzw. ``tcp6``. Unlesbare Zeilen werden übersprungen.

    Der Kernel schreibt jede 32-Bit-Gruppe einer Adresse als Zahl in der Byte-Reihenfolge des
    Rechners; ``byteorder`` ist darum die des Rechners, der die Datei erzeugt hat."""
    out: list[TcpEntry] = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            local = _decode_addr(f[1], byteorder)
            remote = _decode_addr(f[2], byteorder)
            out.append(TcpEntry(local, remote, int(f[3], 16), int(f[7]), int(f[9])))
        except ValueError:
            continue
    return out


def _read_text(path: str) -> str:
    try:
        with open(path, encoding="ascii", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


# --------------------------------------------------------------------------- #
# Netlink sock_diag (gezielte Suche)
# --------------------------------------------------------------------------- #

_NETLINK_SOCK_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20
_NLM_F_REQUEST = 0x1
_NLMSG_ERROR = 2
_NLMSG_HDR = struct.Struct("=IHHII")
_ALL_STATES = 0xFFFFFFFF
_NO_COOKIE = 0xFFFFFFFF
_DIAG_TIMEOUT_S = 1.0


class DiagUnavailable(OSError):
    """Netlink ``sock_diag`` geht hier nicht (Kernel, Sandbox); dann gilt ``/proc/net/tcp``."""


def _diag_once(family: int, local: tuple[str, int], remote: tuple[str, int]) -> TcpEntry | None:
    def packed(host: str) -> bytes:
        raw = ipaddress.ip_address(host).packed
        return raw + b"\0" * (16 - len(raw))

    sockid = (struct.pack("!HH", local[1], remote[1]) + packed(local[0]) + packed(remote[0])
              + struct.pack("=III", 0, _NO_COOKIE, _NO_COOKIE))
    req = struct.pack("=BBBBI", family, socket.IPPROTO_TCP, 0, 0, _ALL_STATES) + sockid
    msg = _NLMSG_HDR.pack(_NLMSG_HDR.size + len(req), _SOCK_DIAG_BY_FAMILY, _NLM_F_REQUEST, 1, 0) + req
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, _NETLINK_SOCK_DIAG)
    except OSError as exc:
        raise DiagUnavailable(exc.errno, "sock_diag nicht verfügbar") from None
    try:
        s.settimeout(_DIAG_TIMEOUT_S)
        s.sendto(msg, (0, 0))
        data = s.recv(8192)
    except OSError as exc:
        raise DiagUnavailable(exc.errno, "sock_diag nicht verfügbar") from None
    finally:
        s.close()
    if len(data) < _NLMSG_HDR.size + 4:
        raise DiagUnavailable(errno.EPROTO, "sock_diag: kurze Antwort")
    _ln, typ, _flags, _seq, _pid = _NLMSG_HDR.unpack_from(data, 0)
    body = data[_NLMSG_HDR.size:]
    if typ == _NLMSG_ERROR:
        err = -struct.unpack_from("=i", body, 0)[0]
        if err in (errno.ENOENT, errno.ESRCH):
            return None  # kein solcher Socket
        raise DiagUnavailable(err, "sock_diag abgelehnt")
    if typ != _SOCK_DIAG_BY_FAMILY or len(body) < 4 + 48 + 20:
        raise DiagUnavailable(errno.EPROTO, "sock_diag: unerwartete Antwort")
    _fam, state = struct.unpack_from("=BB", body, 0)
    uid, inode = struct.unpack_from("=II", body, 4 + 48 + 12)
    return TcpEntry(local, remote, int(state), int(uid), int(inode))


def diag_lookup(client: tuple[str, int], server: tuple[str, int]) -> TcpEntry | None:
    """Client-Socket der Verbindung über Netlink ``sock_diag`` mit dem genauen 4-Tupel.

    ``None``: kein solcher Socket oder einer ohne Inode (TIME_WAIT). :class:`DiagUnavailable`,
    wenn Netlink hier nicht geht. Eine IPv4-Verbindung aus einem IPv6-Socket (IPv4-mapped) wird
    ein zweites Mal als IPv6 gesucht."""
    local = (_norm_ip(client[0]), int(client[1]))
    remote = (_norm_ip(server[0]), int(server[1]))
    v6 = ":" in local[0]
    entry = _diag_once(socket.AF_INET6 if v6 else socket.AF_INET, local, remote)
    if entry is None and not v6:
        mapped = (f"::ffff:{local[0]}", local[1]), (f"::ffff:{remote[0]}", remote[1])
        entry = _diag_once(socket.AF_INET6, *mapped)
        entry = TcpEntry(local, remote, entry.state, entry.uid, entry.inode) if entry else None
    if entry is None or entry.inode == 0:
        return None
    return entry


def find_socket(client: tuple[str, int], server: tuple[str, int], *,
                proc_root: str = PROC, use_diag: bool | None = None) -> TcpEntry | None:
    """Eintrag des Client-Sockets der Verbindung ``client`` → ``server`` oder ``None``.

    ``use_diag`` (Standard: nur mit dem echten ``/proc``): zuerst Netlink ``sock_diag``; nur
    wenn das hier nicht geht, die Tabellen in ``/proc/net`` (vorher nach dem Port gefiltert)."""
    try:
        want_local = (_norm_ip(client[0]), int(client[1]))
        want_remote = (_norm_ip(server[0]), int(server[1]))
    except (ValueError, TypeError, IndexError):
        return None
    if use_diag is None:
        use_diag = proc_root == PROC
    if use_diag:
        try:
            return diag_lookup(want_local, want_remote)
        except DiagUnavailable:
            pass
    port = f":{want_local[1]:04X} "
    best: TcpEntry | None = None
    for name in ("tcp", "tcp6"):
        text = _read_text(f"{proc_root}/net/{name}")
        lines = text.splitlines()
        wanted = "\n".join(lines[:1] + [ln for ln in lines[1:] if port in ln.upper()])
        for e in parse_proc_net(wanted):
            if e.local != want_local or e.remote != want_remote:
                continue
            if e.inode == 0:  # TIME_WAIT und Ähnliches gehören keinem Prozess mehr
                continue
            if best is None or (e.state == _ESTABLISHED and best.state != _ESTABLISHED):
                best = e
    return best


# --------------------------------------------------------------------------- #
# Prozesse
# --------------------------------------------------------------------------- #


def find_holders(inode: int, uid: int, *, proc_root: str = PROC) -> tuple[int, ...]:
    """PIDs aller lesbaren Prozesse mit ``uid``, die ``socket:[inode]`` offen haben."""
    target = f"socket:[{int(inode)}]"
    found: list[int] = []
    try:
        with os.scandir(proc_root) as it:
            entries = [e for e in it if e.name.isdigit()]
    except OSError:
        return ()
    for ent in entries:
        try:
            if ent.stat(follow_symlinks=False).st_uid != uid:
                continue  # fremder oder nicht «dumpable» Prozess (gehört dann root)
            if _holds(f"{ent.path}/fd", target):
                found.append(int(ent.name))
        except OSError:  # Prozess beendet oder fd-Tabelle nicht lesbar
            continue
    return tuple(sorted(found))


def _holds(fd_dir: str, target: str) -> bool:
    with os.scandir(fd_dir) as it:
        for fd in it:
            try:
                if os.readlink(fd.path) == target:
                    return True
            except OSError:
                continue
    return False


def resolve_peer(client: tuple[str, int], server: tuple[str, int], *, uid: int | None = None,
                 proc_root: str = PROC) -> PeerInfo | None:
    """Peer einer Verbindung. ``None``: kein Eintrag (die Verbindung ist schon weg oder kommt
    nicht über Loopback dieses Rechners); der Aufrufer schliesst sie ohne Antwort.

    Gehört der Socket nicht ``uid`` (Standard: die eigene), wird nicht nach Prozessen gesucht;
    der Aufrufer lehnt die Verbindung dann ohnehin ab."""
    uid = os.getuid() if uid is None else uid
    entry = find_socket(client, server, proc_root=proc_root)
    if entry is None:
        return None
    if entry.uid != uid:
        return PeerInfo(uid=entry.uid, inode=entry.inode, pids=())
    pids = find_holders(entry.inode, entry.uid, proc_root=proc_root)
    return PeerInfo(uid=entry.uid, inode=entry.inode, pids=pids)


def proc_info(pid: int, *, proc_root: str = PROC) -> ProcInfo | None:
    """PID, PPID, Startzeit und ``comm`` aus ``/proc/<pid>/stat``; ``None``, wenn es ihn nicht gibt."""
    text = _read_text(f"{proc_root}/{int(pid)}/stat")
    lpar, rpar = text.find("("), text.rfind(")")
    if lpar < 0 or rpar < lpar:
        return None
    rest = text[rpar + 1:].split()
    try:
        return ProcInfo(pid=int(pid), ppid=int(rest[1]), start=int(rest[19]), comm=text[lpar + 1:rpar])
    except (IndexError, ValueError):
        return None


def proc_uid(pid: int, *, proc_root: str = PROC) -> int | None:
    """Reale UID aus ``/proc/<pid>/status`` (Zeile ``Uid``)."""
    for line in _read_text(f"{proc_root}/{int(pid)}/status").splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                return None
    return None


def same_process(ref: ProcInfo, *, proc_root: str = PROC) -> bool:
    """Lebt der Prozess noch, und ist er derselbe (gleiche Startzeit, keine wiederverwendete PID)?"""
    now = proc_info(ref.pid, proc_root=proc_root)
    return now is not None and now.start == ref.start


def _pass_through(comm: str) -> bool:
    return comm in PASS_THROUGH or comm.startswith("python")


def sshd_ancestor(pid: int, *, uid: int | None = None, proc_root: str = PROC,
                  max_steps: int = MAX_ANCESTOR_STEPS) -> ProcInfo | None:
    """Der sshd-Prozess, von dem ``pid`` abstammt (Vertrag 3.4), oder ``None``.

    Höchstens ``max_steps`` Stufen nach oben; gesucht ist ein Prozess mit ``comm`` ``sshd``
    oder ``sshd-session`` und der eigenen realen UID. Dazwischen nur Shells oder Python."""
    uid = os.getuid() if uid is None else uid
    me = proc_info(pid, proc_root=proc_root)
    if me is None:
        return None
    cur = me
    for _ in range(max_steps):
        if cur.ppid <= 1:
            return None
        parent = proc_info(cur.ppid, proc_root=proc_root)
        if parent is None:
            return None
        if parent.comm in SSHD_COMMS:
            return parent if proc_uid(parent.pid, proc_root=proc_root) == uid else None
        if not _pass_through(parent.comm):
            return None
        cur = parent
    return None
