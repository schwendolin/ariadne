"""Echter Daemon mit Web-Server und Fixture-Projekt für die Browsertests der Oberfläche.

Vertrag v0.1-Oberfläche, Abschnitt 8 (Teststrategie). Besitzer ab Phase 2: Teil «backend-ui»
(er ergänzt vorbereitete Entscheide wie Findings, «Neu seit» und Denkanstösse); die UI-Teile
nutzen es über ``webui/e2e/fixtures.ts`` (``loginDaemon``, ``daemonState``) und
``npm run test:e2e:daemon``.

Aufruf (aus dem Repo-Wurzelordner, mit der venv)::

    .venv/bin/python -m tests.e2e.ui_fixture --port 41234 --static webui/.e2e/dist-prod \
        --state-file webui/.e2e/daemon.json [--scenario ms2|empty|noproject|locked]

* Isoliert: eigener Wegwerf-Ordner für HOME und XDG_* (nie die Dateien des Benutzers), eigener
  Operator-Tresor, Port auf ``127.0.0.1``. Der Ordner wird beim Ende gelöscht (ausser ``--keep``).
* Daten wie im Briefing Anhang A, soweit die echten Parser sie liefern: Projekt ``ms2`` mit Scope
  ``192.168.56.0/24``, nmap ``-sV -sC`` gegen 192.168.56.101 (Golden ms2_sv_sc), msf-Sitzung mit
  Kontext «auto» in T2, mehrdeutiger Callback in T3 (Kontextvorschlag), eine Eingabe ohne Echo,
  Schlüsselschritte Foothold und Loot, Zugriff root per Entscheid, Tag und Notiz. Dazu (Teil
  «backend-ui»): «Neu seit» mit ``seen_at`` nach dem Scan (alles danach ist neu), eine Scope-Warnung
  (``ping`` gegen 10.66.66.66 in T1) und das Finding F1 «vsftpd 2.3.4 Backdoor» mit Beleg.
* Schreibt, sobald alles ausgewertet ist, ``--state-file`` (JSON: ``base``, ``port``, ``ctl``,
  ``project_id``, ``home``) und meldet ``READY`` auf stdout. Läuft bis SIGTERM bzw. SIGINT (mit
  ``--watch-stdin`` auch bis stdin endet).
* Anmeldecodes holt der Test selbst über ``ctl.sock`` (``{"op": "ui.code", "args": {"via":
  "local"}}``); das Token bindet der Daemon an den Browser-Prozess (R2).
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import shutil
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from tests.core.conftest import OWN_SECRET, PASSPHRASE, make_env

REPO = Path(__file__).resolve().parents[2]
GOLDEN = REPO / "tests" / "golden"
NET = "192.168.56.0/24"
TARGET = "192.168.56.101"
KALI = "192.168.56.102"


def _parse(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, required=True, help="freier Port auf 127.0.0.1")
    ap.add_argument("--static", type=Path, required=True, help="gebaute SPA (vite build --outDir …)")
    ap.add_argument("--state-file", type=Path, required=True)
    ap.add_argument("--scenario", choices=("ms2", "empty", "noproject", "locked"), default="ms2")
    ap.add_argument("--keep", action="store_true", help="Wegwerf-Ordner nicht löschen")
    ap.add_argument("--watch-stdin", action="store_true", help="beenden, sobald stdin endet")
    return ap.parse_args(argv)


async def _fixture_ms2(d: Any, paths: Any) -> tuple[str, list[Any]]:
    from ariadne._shim import protocol as P
    from ariadne.daemon.terminal import normalize_host
    from ariadne.store.api import AppendItem
    from tests.core.fakeshim import FakeShim, ctl_ok
    from tests.integration.helpers import Term
    from tests.web.api.helpers import sync

    res = await ctl_ok(paths.ctl_sock, "start", slug="ms2", targets=[NET])
    pid = str(res["id"])
    ws = Path(res["workspace"])
    (ws / "scans").mkdir(exist_ok=True)
    xml = (GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes()
    text = (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_bytes()
    (ws / "scans" / "ms2.xml").write_bytes(xml)

    # T1 «scan»: nmap gegen .101
    s1 = await FakeShim(paths.term_sock).connect(proto=2)
    await s1.wait_state(rec="on")
    t1 = Term(s1)
    await t1.command(f"nmap -sV -sC -oA scans/ms2 {TARGET}", text.replace(b"\n", b"\r\n"), cwd=str(ws))
    await t1.acked()
    await sync(d)

    # «Neu seit» (E106): Der Tab wurde nach dem Scan unsichtbar; alles Folgende ist neu
    from ariadne.web.api.ui_state import state_set

    await asyncio.to_thread(state_set, d.project, "seen_at", str(time.time_ns()))
    await asyncio.sleep(0.01)

    # Scope-Warnung (E67, 18.4): ein Befehl in T1 gegen eine Adresse ausserhalb des Scopes
    await t1.command("ping -c1 10.66.66.66", b"1 packets transmitted, 0 received\r\n", cwd=str(ws))
    await t1.acked()

    # T2 «msf»: Sitzung über die vsftpd-Hintertür (Kontext automatisch, E23)
    s2 = await FakeShim(paths.term_sock).connect(proto=2)
    await s2.wait_state(rec="on")
    t2 = Term(s2)
    await t2.command(
        "msfconsole -q",
        b"msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run\r\n"
        b"[*] 192.168.56.101:21 - Banner: 220 (vsFTPd 2.3.4)\r\n"
        b"[+] 192.168.56.101:21 - UID: uid=0(root) gid=0(root)\r\n"
        b"[*] Command shell session 1 opened (192.168.56.102:4444 -> 192.168.56.101:6200)\r\n",
        cwd=str(ws),
        end=False,
    )
    await t2.acked()

    # T3 «listener»: Callback von .101 und ein gefälschter zweiter im Output (Kontextvorschlag)
    s3 = await FakeShim(paths.term_sock).connect(proto=2)
    await s3.wait_state(rec="on")
    t3 = Term(s3)
    await t3.command(
        "nc -lvnp 4445",
        b"listening on [any] 4445 ...\r\n"
        b"connect to [192.168.56.102] from (UNKNOWN) [192.168.56.101] 49158\r\n"
        b"id\r\nuid=0(root) gid=0(root)\r\n"
        b"connect to [192.168.56.102] from (UNKNOWN) [10.66.66.66] 31337\r\n",
        cwd=str(ws),
        end=False,
    )
    await t3.acked()

    # Eingabe ohne Echo (E104) in T3
    off = t3.off
    t3.seq += 1
    secret = b"geheim-731\r"
    await s3.send(P.encode_input(t3.seq, off, off, time.time_ns(), time.monotonic_ns(), secret, no_echo=True))
    t3.seq += 1
    await s3.outx(t3.seq, off, b"\r\n$ ")
    t3.off += 4
    await s3.wait_ack(t3.seq)

    # Entscheide wie im Standbild: Schlüsselschritte, Zugriff root, Tag, Notiz, Terminalnamen
    host = normalize_host(TARGET)
    for kind, header in (
        ("d.keystep.mark", {"step": "foothold", "host": host, "note": "vsftpd 2.3.4 Backdoor"}),
        ("d.keystep.mark", {"step": "loot", "host": host, "note": "/etc/shadow"}),
        ("d.status.access", {"subject": host, "value": "admin"}),
        ("d.status.work", {"subject": host, "value": "in_progress"}),
        ("d.tag.add", {"subject": host, "tag": "linux"}),
        ("d.note.set", {"subject": host, "text": "vsftpd-Backdoor geht, Samba noch prüfen"}),
        ("d.terminal.label", {"terminal_id": s1.terminal_id, "label": "scan"}),
        ("d.terminal.label", {"terminal_id": s2.terminal_id, "label": "msf"}),
        ("d.terminal.label", {"terminal_id": s3.terminal_id, "label": "listener"}),
    ):
        d.submit(AppendItem(kind, header, origin="webui"))
    d.flush()
    await sync(d)

    # Finding F1 (E113, 18.5) wie «Als Finding» aus der Belegansicht: Beleg und «angelegt aus»
    svc = f"svc:{host}|tcp/21"

    def refs(conn: Any) -> tuple[str | None, str | None]:
        row = conn.execute(
            "SELECT claim_key, first_unit FROM claim WHERE subject_identifier = ? "
            "AND predicate = 'service.product'",
            (svc,),
        ).fetchone()
        return (str(row[0]), str(row[1])) if row else (None, None)

    claim_key, unit_id = await d.ingest.query(refs)
    finding: dict[str, Any] = {
        "title": "vsftpd 2.3.4 Backdoor",
        "severity": "critical",
        "status": "draft",
        "affected": [svc],
        "description": "Die Hintertür in **vsftpd 2.3.4** öffnet eine Root-Shell auf Port 6200.",
        "remediation": "vsftpd aktualisieren oder den Dienst abschalten.",
        "attack": [{"id": "T1190", "supported": True}],
        "cves": [{"id": "CVE-2011-2523"}],
        "evidence": [{"claim_key": claim_key}] if claim_key else [],
    }
    if unit_id:
        finding["created_from"] = {"unit_id": unit_id}
    d.submit(AppendItem("d.finding.create", finding, origin="webui"))
    d.flush()
    await sync(d)
    return pid, [s1, s2, s3]  # Shims offen halten, solange der Fixture-Prozess läuft


async def _main(args: argparse.Namespace, root: Path) -> int:
    from ariadne.crypto.vault import OperatorVault
    from ariadne.daemon.core import Daemon
    from ariadne.daemon.ingest import IngestService
    from ariadne.paths import default_paths
    from ariadne.web.integration import WebExtension
    from tests.core.fakeshim import close_all, ctl_ok

    env = make_env(root)
    env.pop("ARIADNE_WEB", None)
    os.environ.update(env)
    paths = default_paths(env)
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(f"[ui]\nport = {args.port}\n", encoding="utf-8")
    _code, op = OperatorVault(paths.operator_dir).create_and_unlock(PASSPHRASE, handle="tester")
    op.add_secret("sudo", OWN_SECRET)
    op.save()

    async def no_clock() -> dict[str, Any]:
        return {"detail": "ui-fixture"}

    ext = WebExtension(paths, static_root=args.static.resolve())
    d = Daemon(paths, check_peer_comm=False, operator=op, batch_interval=0.02, clock_check=no_clock,
               ingest=IngestService(debounce=0.05, periodic=0), local_addrs=lambda: (KALI,), extensions=[ext])
    await d.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    if args.watch_stdin:
        loop.add_reader(sys.stdin.fileno(), lambda: stop.set() if not sys.stdin.buffer.read1(4096) else None)
    shims: list[Any] = []
    try:
        pid: str | None = None
        if args.scenario in ("ms2", "locked"):
            pid, shims = await _fixture_ms2(d, paths)
        elif args.scenario == "empty":
            pid = str((await ctl_ok(paths.ctl_sock, "start", slug="ms2", targets=[NET]))["id"])
        if args.scenario == "locked":
            await ctl_ok(paths.ctl_sock, "lock")
        if ext.server is None:
            print(f"FEHLER: Web-Server nicht gestartet ({ext.error})", flush=True)
            return 2
        port = ext.server.port
        state = {"base": f"http://127.0.0.1:{port}", "port": port, "ctl": str(paths.ctl_sock),
                 "project_id": pid, "home": str(root), "scenario": args.scenario}
        args.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = args.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        tmp.replace(args.state_file)
        print("READY", flush=True)
        await stop.wait()
        return 0
    finally:
        for s in shims:
            with contextlib.suppress(Exception):
                await s.close()
        await d.stop()
        await close_all()


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    root = Path(tempfile.mkdtemp(prefix="ariadne-ui-e2e-"))
    try:
        return asyncio.run(_main(args, root))
    finally:
        with contextlib.suppress(FileNotFoundError):
            args.state_file.unlink()
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
