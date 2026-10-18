"""Hilfen für die Tests der Sicherung: Quell-Installation, Empfänger, Entschlüsseln, Datei-Hashes."""

from __future__ import annotations

import dataclasses
import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pyrage
from pyrage import x25519

from ariadne.crypto.vault import OperatorVault, UnlockedOperator
from ariadne.paths import Paths, default_paths
from ariadne.project.service import ProjectService
from tests.core.conftest import make_env

CANARY = b"CANARY-loot-7f3a9c-PLAINTEXT"
TARGET = "10.10.10.3"


def new_identity() -> tuple[Any, str]:
    ident = x25519.Identity.generate()
    return ident, str(ident.to_public())


def write_recipients(paths: Paths, *recipients: str, mode: int = 0o600) -> Path:
    paths.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    f = paths.config_dir / "backup-recipients.txt"
    f.write_text("# Mac und Recovery\n" + "".join(f"{r}\n" for r in recipients))
    os.chmod(f, mode)
    return f


def make_project(paths: Paths, op: UnlockedOperator, slug: str, *, close: bool = True,
                 canary: bytes = CANARY) -> tuple[int, str] | None:
    """Projekt anlegen, Arbeitsbereich füllen, einmal öffnen und schliessen (``head.json``)."""
    svc = ProjectService(paths, op)
    svc.create(slug, [TARGET])
    ws = paths.projects_root / slug
    (ws / "loot" / "flag.txt").write_bytes(canary + b"\n")
    (ws / "scans" / "nmap.xml").write_bytes(b"<nmaprun>" + os.urandom(3000).hex().encode() + b"</nmaprun>")
    (ws / "scans" / "exploit.sh").write_bytes(b"#!/bin/sh\necho hi\n")
    os.chmod(ws / "scans" / "exploit.sh", 0o700)
    if not close:
        return None
    p = svc.open(slug)
    p.journal.append("system.checkpoint", {"reason": "manual", "head_seq": 1, "head_hash": "00" * 32})
    return p.close()


def source_install(paths: Paths, op: UnlockedOperator, slugs: tuple[str, ...] = ("lame",)) -> dict[str, Any]:
    ident, recip = new_identity()
    _, recovery = new_identity()
    write_recipients(paths, recip, recovery)
    (paths.config_dir / "config.toml").write_text('[recording]\npause_minutes = 12\n')
    os.chmod(paths.config_dir / "config.toml", 0o600)
    heads = {slug: make_project(paths, op, slug) for slug in slugs}
    return {"identity": ident, "recipient": recip, "heads": heads}


def target_paths(base: Path) -> tuple[dict[str, str], Paths]:
    env = make_env(base)
    return env, default_paths(env)


def decrypt(data: bytes, ident: Any) -> bytes:
    return pyrage.decrypt(data, [ident])


def members(inner: bytes) -> list[tarfile.TarInfo]:
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r:", encoding="utf-8", errors="surrogateescape") as tf:
        return tf.getmembers()


def manifest_of(inner: bytes) -> dict[str, Any]:
    with tarfile.open(fileobj=io.BytesIO(inner), mode="r:", encoding="utf-8", errors="surrogateescape") as tf:
        first = tf.getmembers()[0]
        assert first.name == "ariadne-backup.json"
        fh = tf.extractfile(first)
        assert fh is not None
        return json.loads(fh.read())


def tree_hashes(root: Path, *, skip_vault_extras: bool = True) -> dict[str, str]:
    """SHA-256 aller regulären Dateien unter ``root`` (ohne ``.lock``, ``derived*``, ``*-shm``)."""
    out = {}
    for f in sorted(root.rglob("*")):
        if f.is_symlink() or not f.is_file():
            continue
        name = f.name
        if skip_vault_extras and (name == ".lock" or name.startswith("derived") or name.endswith("-shm")):
            continue
        out[str(f.relative_to(root))] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def clone_op_for(op: UnlockedOperator, paths: Paths) -> UnlockedOperator:
    """Derselbe Operator, aber mit dem Tresor unter ``paths`` (für zurückgespielte Installationen)."""
    return dataclasses.replace(op, vault=OperatorVault(paths.operator_dir), _secrets=list(op.own_secrets),
                               _api_keys={})


def cli_env(env: dict[str, str]) -> dict[str, str]:
    return {**env, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}


def cli(env: dict[str, str], *args: str, stdin: Any = subprocess.DEVNULL, stdout: Any = None,
        pass_fds: tuple[int, ...] = (), timeout: float = 90,
        input: bytes | None = None) -> subprocess.CompletedProcess[bytes]:  # noqa: A002
    """``ariadne …`` als Subprozess; ``input`` schickt Bytes über eine Pipe nach stdin."""
    kw: dict[str, Any] = {"input": input} if input is not None else {"stdin": stdin}
    return subprocess.run([sys.executable, "-m", "ariadne.cli.main", *args], env=cli_env(env),
                          stdout=stdout if stdout is not None else subprocess.PIPE, stderr=subprocess.PIPE,
                          pass_fds=pass_fds, timeout=timeout, check=False, **kw)
