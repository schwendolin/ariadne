"""Peer über ``/proc`` (R2, Vertrag 3.4): Parser mit Fixtures, echte Sockets, sshd-Vorfahren."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from ariadne.web.peer import (
    PeerInfo,
    find_holders,
    find_socket,
    parse_proc_net,
    proc_info,
    resolve_peer,
    same_process,
    sshd_ancestor,
)

HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout "
          "inode\n")
# 127.0.0.1:54321 -> 127.0.0.1:7330, ESTABLISHED, UID 1000, Inode 4242 (aus einer x86-Maschine)
V4 = HEADER + (
    "   0: 0100007F:1CA2 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n"
    "   1: 0100007F:D431 0100007F:1CA2 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1\n"
    "   2: 0100007F:1CA2 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 4243 1\n"
    "   3: 0100007F:D432 0100007F:1CA2 06 00000000:00000000 03:00001000 00000000     0        0 0 3\n"
    "kaputt\n"
)
# [::1]:40000 -> [::1]:7330 (UID 1001) und IPv4-mapped ::ffff:127.0.0.1:40001 -> 127.0.0.1:7330
V6 = HEADER + (
    "   0: 00000000000000000000000001000000:9C40 00000000000000000000000001000000:1CA2 01 "
    "00000000:00000000 00:00000000 00000000  1001        0 5151 1\n"
    "   1: 0000000000000000FFFF00000100007F:9C41 0000000000000000FFFF00000100007F:1CA2 01 "
    "00000000:00000000 00:00000000 00000000  1000        0 6161 1\n"
)


def _fake_proc(root: Path, *, tcp: str = V4, tcp6: str = V6) -> Path:
    (root / "net").mkdir(parents=True)
    (root / "net" / "tcp").write_text(tcp)
    (root / "net" / "tcp6").write_text(tcp6)
    return root


def _fake_pid(root: Path, pid: int, *, comm: str, ppid: int, start: int = 100, uid: int | None = None,
              sockets: tuple[int, ...] = (), fd_dir: bool = True) -> None:
    d = root / str(pid)
    d.mkdir()
    rest = ["S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 10
    (d / "stat").write_text(f"{pid} ({comm}) " + " ".join(rest) + "\n")
    u = os.getuid() if uid is None else uid
    (d / "status").write_text(f"Name:\t{comm}\nUid:\t{u}\t{u}\t{u}\t{u}\n")
    if fd_dir:
        (d / "fd").mkdir()
        for i, ino in enumerate(sockets):
            os.symlink(f"socket:[{ino}]", d / "fd" / str(i + 3))
            os.symlink("/dev/null", d / "fd" / str(i + 100))


def test_parse_ipv4_ipv6_and_mapped():
    v4 = parse_proc_net(V4, byteorder="little")
    assert [(e.local, e.remote, e.state, e.uid, e.inode) for e in v4[:2]] == [
        (("127.0.0.1", 7330), ("0.0.0.0", 0), 0x0A, 1000, 111),
        (("127.0.0.1", 54321), ("127.0.0.1", 7330), 0x01, 1000, 4242),
    ]
    assert len(v4) == 4  # kaputte Zeile übersprungen
    v6 = parse_proc_net(V6, byteorder="little")
    assert v6[0].local == ("::1", 40000) and v6[0].remote == ("::1", 7330)
    assert v6[1].local == ("127.0.0.1", 40001)  # IPv4-mapped gilt als IPv4


@pytest.mark.skipif(sys.byteorder != "little", reason="Fixture stammt von einer Little-Endian-Maschine")
def test_find_socket_matches_client_side_only(tmp_path):
    root = str(_fake_proc(tmp_path / "proc"))
    e = find_socket(("127.0.0.1", 54321), ("127.0.0.1", 7330), proc_root=root)
    assert e is not None and e.inode == 4242  # nicht 4243 (die Server-Seite)
    assert find_socket(("127.0.0.1", 54322), ("127.0.0.1", 7330), proc_root=root) is None  # TIME_WAIT
    e6 = find_socket(("::ffff:127.0.0.1", 40001), ("127.0.0.1", 7330), proc_root=root)
    assert e6 is not None and e6.inode == 6161
    assert find_socket(("::1", 40000), ("::1", 7330), proc_root=root).uid == 1001
    assert find_socket(("kein", 1), ("127.0.0.1", 7330), proc_root=root) is None


@pytest.mark.skipif(sys.byteorder != "little", reason="Fixture stammt von einer Little-Endian-Maschine")
def test_holders_readable_unreadable_and_foreign(tmp_path):
    me = os.getuid()
    root = _fake_proc(tmp_path / "proc", tcp=V4.replace("  1000        0", f"  {me:>4}        0"))
    _fake_pid(root, 300, comm="firefox", ppid=1, sockets=(4242,))
    _fake_pid(root, 301, comm="sshd-session", ppid=1, fd_dir=False)  # nicht lesbar
    _fake_pid(root, 302, comm="curl", ppid=1, sockets=(9999,))
    assert find_holders(4242, me, proc_root=str(root)) == (300,)
    assert find_holders(6161, me, proc_root=str(root)) == ()
    assert find_holders(4242, me + 1, proc_root=str(root)) == ()  # Prozesse anderer UID zählen nicht
    peer = resolve_peer(("127.0.0.1", 54321), ("127.0.0.1", 7330), proc_root=str(root))
    assert peer == PeerInfo(uid=me, inode=4242, pids=(300,)) and peer.readable
    if me != 1001:
        foreign = resolve_peer(("::1", 40000), ("::1", 7330), proc_root=str(root))
        assert foreign == PeerInfo(uid=1001, inode=5151, pids=())  # fremde UID: keine Suche
    assert resolve_peer(("127.0.0.1", 1), ("127.0.0.1", 7330), proc_root=str(root)) is None


def test_real_tcp_connection_resolves_to_this_process():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    cli = socket.create_connection(srv.getsockname())
    conn, _ = srv.accept()
    try:
        peer = resolve_peer(cli.getsockname(), srv.getsockname())
        assert peer is not None and peer.uid == os.getuid() and os.getpid() in peer.pids
        # die Server-Seite ist nicht der Client
        assert find_socket(conn.getsockname(), conn.getpeername()).inode != peer.inode
    finally:
        for s in (cli, conn, srv):
            s.close()


def test_real_connection_from_child_process():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    code = ("import socket,sys,time; s=socket.create_connection(('127.0.0.1', int(sys.argv[1]))); "
            "print(s.getsockname()[1], flush=True); sys.stdin.read(); s.close()")
    child = subprocess.Popen([sys.executable, "-I", "-c", code, str(srv.getsockname()[1])],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    conn = None
    try:
        port = int(child.stdout.readline())
        conn, _ = srv.accept()
        peer = resolve_peer(("127.0.0.1", port), srv.getsockname())
        assert peer is not None and peer.pids == (child.pid,)
        info = proc_info(child.pid)
        assert info is not None and info.ppid == os.getpid() and same_process(info)
    finally:
        child.stdin.close()
        child.wait(10)
        child.stdout.close()
        if conn is not None:
            conn.close()
        srv.close()
    assert not same_process(info)  # beendet


def test_proc_info_parses_comm_with_parentheses(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    _fake_pid(root, 77, comm="a) (b", ppid=5, start=999)
    info = proc_info(77, proc_root=str(root))
    assert info is not None and info.comm == "a) (b" and info.ppid == 5 and info.start == 999
    assert proc_info(78, proc_root=str(root)) is None


def test_sshd_ancestor_rules(tmp_path):
    root = tmp_path / "proc"
    root.mkdir()
    me = os.getuid()
    # sshd-session (10) -> zsh (11) -> ariadne (12)
    _fake_pid(root, 10, comm="sshd-session", ppid=1)
    _fake_pid(root, 11, comm="zsh", ppid=10)
    _fake_pid(root, 12, comm="ariadne", ppid=11)
    assert sshd_ancestor(12, uid=me, proc_root=str(root)).pid == 10
    # direkt unter sshd (OpenSSH vor 9.8)
    _fake_pid(root, 20, comm="sshd", ppid=1)
    _fake_pid(root, 21, comm="python3", ppid=20)
    assert sshd_ancestor(21, uid=me, proc_root=str(root)).pid == 20
    # fremder Prozess dazwischen: nein
    _fake_pid(root, 30, comm="sshd", ppid=1)
    _fake_pid(root, 31, comm="tmux: server", ppid=30)
    _fake_pid(root, 32, comm="ariadne", ppid=31)
    assert sshd_ancestor(32, uid=me, proc_root=str(root)) is None
    # sshd einer anderen UID: nein
    _fake_pid(root, 40, comm="sshd", ppid=1, uid=me + 1)
    _fake_pid(root, 41, comm="ariadne", ppid=40)
    assert sshd_ancestor(41, uid=me, proc_root=str(root)) is None
    # zu weit oben (mehr als 4 Stufen): nein
    _fake_pid(root, 50, comm="sshd", ppid=1)
    for i, comm in enumerate(["bash", "sh", "zsh", "dash", "python3"]):
        _fake_pid(root, 51 + i, comm=comm, ppid=50 + i)
    assert sshd_ancestor(55, uid=me, proc_root=str(root)) is None
    assert sshd_ancestor(54, uid=me, proc_root=str(root)).pid == 50
    # lokaler Aufrufer ohne sshd: nein
    _fake_pid(root, 60, comm="xfce4-terminal", ppid=1)
    _fake_pid(root, 61, comm="zsh", ppid=60)
    _fake_pid(root, 62, comm="ariadne", ppid=61)
    assert sshd_ancestor(62, uid=me, proc_root=str(root)) is None
    assert sshd_ancestor(999, uid=me, proc_root=str(root)) is None
