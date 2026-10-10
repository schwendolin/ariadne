"""Ziele aus argv (Aktivitätsprotokoll, Scope-Warnung; Architektur 5.13)."""

from __future__ import annotations

import pytest

from ariadne.ctxrules import split_command
from ariadne.scope.targets import analyze_targets, extract_targets, tool_name


@pytest.mark.parametrize("cmd,targets", [
    ("nmap -sV -p- -oA scans/lame 10.10.10.3", ["10.10.10.3"]),
    ("sudo nmap -sU --top-ports 100 10.10.10.0/24", ["10.10.10.0/24"]),
    ("nmap -Pn 10.10.10.1-50 lame.htb --exclude 10.10.10.7", ["10.10.10.1-50", "lame.htb"]),
    ("nmap --script=vuln -T4 -e tun0 10.10.10.3 10.10.10.4", ["10.10.10.3", "10.10.10.4"]),
    ("proxychains4 -q nmap -sT 172.16.1.0/24", ["172.16.1.0/24"]),
    ("ssh -i id_rsa -p 2222 root@10.10.10.5", ["10.10.10.5"]),
    ("ssh -J jump@10.0.0.1 admin@172.16.1.5", ["10.0.0.1", "172.16.1.5"]),
    ("ssh ssh://root@[fe80::1]:22", ["fe80::1"]),
    ("curl -s -H 'Host: x' http://10.10.10.3/admin", ["http://10.10.10.3/admin"]),
    ("curl 10.10.10.3:8080/x", ["http://10.10.10.3:8080/x"]),
    ("curl --url https://lame.htb/", ["https://lame.htb/"]),
    ("wget http://10.10.10.3/shell.sh -O /tmp/s", ["http://10.10.10.3/shell.sh"]),
    ("gobuster dir -u http://10.10.10.3 -w /usr/share/wordlists/dirb/common.txt", ["http://10.10.10.3"]),
    ("gobuster vhost -u http://lame.htb -w subs.txt", ["http://lame.htb"]),
    ("ffuf -u http://10.10.10.3/FUZZ -w words.txt", ["http://10.10.10.3/FUZZ"]),
    ("feroxbuster -u https://lame.htb -x php", ["https://lame.htb"]),
    ("nxc smb 10.10.10.0/24 -u admin -p pw", ["10.10.10.0/24"]),
    ("netexec winrm 10.10.10.161 -u a -H b", ["10.10.10.161"]),
    ("crackmapexec smb 10.10.10.3 --shares", ["10.10.10.3"]),
    ("smbclient //10.10.10.3/tmp -U guest%", ["10.10.10.3"]),
    ("smbclient -L //10.10.10.3 -N", ["10.10.10.3"]),
    ("smbclient '\\\\10.10.10.3\\share' -N", ["10.10.10.3"]),
    ("evil-winrm -i 10.10.10.161 -u administrator -H aad3b", ["10.10.10.161"]),
    ("hydra -l admin -P rockyou.txt ssh://10.10.10.3", ["10.10.10.3"]),
    ("hydra -L u.txt -P p.txt 10.10.10.3 ftp", ["10.10.10.3"]),
    ("nikto -h http://10.10.10.3", ["http://10.10.10.3"]),
    ("nikto -h 10.10.10.3 -p 8080", ["10.10.10.3"]),
    ("impacket-secretsdump corp/admin:pw@10.0.0.5", ["10.0.0.5"]),
    ("secretsdump.py -just-dc corp/admin@dc01.corp.local", ["dc01.corp.local"]),
    ("python3 GetNPUsers.py corp.local/ -dc-ip 10.0.0.1 -usersfile u.txt", ["10.0.0.1"]),
    ("impacket-psexec administrator@dc01.corp.local", ["dc01.corp.local"]),
    ("impacket-mssqlclient sa@10.10.10.59 -windows-auth", ["10.10.10.59"]),
    ("ping -c 3 10.10.10.3", ["10.10.10.3"]),
    ("nc -nv 10.10.10.3 21", ["10.10.10.3"]),
    ("nc -lvnp 4444", []),
    ("rlwrap nc -lvnp 4444", []),
    ("ls -la", []),
    ("cat /etc/hosts", []),
    ("", []),
])
def test_extract_targets(cmd, targets):
    assert extract_targets(split_command(cmd)) == targets


@pytest.mark.parametrize("cmd,files", [
    ("nmap -iL hosts.txt -sV", ["hosts.txt"]),
    ("crackmapexec smb hosts.txt -u a -p b", ["hosts.txt"]),
    ("hydra -M targets.txt ssh", ["targets.txt"]),
    ("wget -i urls.txt", ["urls.txt"]),
])
def test_target_files_are_only_reported(cmd, files, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # Dateien existieren nicht; sie werden nie gelesen
    t = analyze_targets(split_command(cmd))
    assert t.input_files == files
    assert not t.targets


def test_no_dns_and_no_fs_access(monkeypatch):
    import socket

    def boom(*a, **k):
        raise AssertionError("keine Namensauflösung erlaubt")

    monkeypatch.setattr(socket, "getaddrinfo", boom)
    monkeypatch.setattr(socket, "gethostbyname", boom)
    assert extract_targets(["nmap", "lame.htb", "-iL", "/etc/shadow"]) == ["lame.htb"]


def test_tool_name():
    assert tool_name(["sudo", "-u", "root", "/usr/bin/nmap", "-sV"]) == "nmap"
    assert tool_name(["python3", "/opt/impacket/examples/psexec.py", "x@y"]) == "psexec"
    assert tool_name(["impacket-secretsdump"]) == "secretsdump"
    assert tool_name([]) == ""


def test_target_count_is_bounded():
    argv = ["nmap"] + [f"10.0.{i // 250}.{i % 250}" for i in range(500)]
    assert len(extract_targets(argv)) == 64
