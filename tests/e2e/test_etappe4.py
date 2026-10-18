"""End-to-End Etappe 4: ein Durchlauf als Nutzer mit KI, Screenshots, Finding, Phasen, Export, Sicherung.

Alles mit echten Prozessen in einem isolierten HOME: CLI per Subprozess, Daemon mit Web-Server auf einem
freien Loopback-Port, zsh mit Shim im PTY, Auswertung mit Parsern im Worker, eigener X-Server (Xvfb) für die
Screenshots. Die KI ist ein Fake-Ollama auf ``127.0.0.1`` (Anbieter ``local``, Modell ``test-model``); er
antwortet mit einem festen Denkanstoss auf den FTP-Dienst aus dem Lagebild. Der «Browser» ist ``httpx`` wie in
:mod:`tests.e2e.test_dashboard`.

Ablauf: ``setup``, ``init``, ``ai setup --provider local``, ``start ms2`` mit dem Fixture-Netz, nmap im
aufgezeichneten Terminal, ``F12 s`` im PTY, Anmeldung am Dashboard, Screenshot und KI-Denkanstoss aus dem
Dashboard, Finding, Phase eines Befehls korrigieren, Export ``cys`` und ``htb``, ``stop``, ``backup``.
"""

from __future__ import annotations

import io
import json
import re
import shutil
import tarfile
import threading
import time
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from tests.e2e.helpers import PASSPHRASE, Lab, expect_title, hotkey, run_cmd
from tests.e2e.test_dashboard import Browser, _host, _ui_login
from tests.integration.helpers import GOLDEN
from tests.remote.helpers import free_port
from tests.screenshots.conftest import Window, xserver  # noqa: F401 - eigener X-Server

NET = "192.168.56.0/24"
TARGET = "192.168.56.101"
KALI_IP = "192.168.56.102"
FINDING = "vsftpd 2.3.4 mit Hintertür"
PNG = b"\x89PNG\r\n\x1a\n"


def _answer(sid: str) -> dict[str, Any]:
    return {
        "anstoesse": [
            {
                "art": "hypothese",
                "titel": "Anonymer Zugang auf dem FTP-Dienst",
                "begruendung": "Der Dienst ist offen und noch nicht auf anonyme Anmeldung geprüft.",
                "bestaetigt_wenn": "Die Anmeldung als anonymous gelingt.",
                "widerlegt_wenn": "Der Dienst verlangt ein Passwort.",
                "belege": [sid],
                "pruefziel": "PZ-AUTH-ANON",
                "frage": "Welche Daten gibt der Dienst ohne Anmeldung preis?",
                "richtung": "Anonyme Anmeldung prüfen und die Antwort lesen.",
                "vorlagen": [{"vorlage": "nmap-ftp-anon", "ziel": sid}],
            }
        ],
        "injection_verdacht": False,
        "injection_hinweis": "",
    }


class FakeOllama:
    """``GET /api/version`` und ``POST /api/chat`` wie Ollama, nur auf 127.0.0.1. Merkt sich die Anfragen."""

    def __init__(self) -> None:
        self.requests: list[bytes] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a: Any) -> None:  # keine Ausgabe
                return

            def _send(self, body: dict[str, Any]) -> None:
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                self._send({"version": "0.0-test"})

            def do_POST(self) -> None:  # noqa: N802
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append(raw)
                user = next(m["content"] for m in json.loads(raw)["messages"] if m["role"] == "user")
                m = re.search(r"\b(S\d+) 21/tcp ftp\b", user)
                text = json.dumps(_answer(m.group(1) if m else "S1"))
                self._send(
                    {
                        "model": "test-model",
                        "message": {"role": "assistant", "content": text},
                        "done": True,
                        "done_reason": "stop",
                        "prompt_eval_count": 1200,
                        "eval_count": 300,
                    }
                )

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = int(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def _until(cond: Callable[[], Any], seconds: float, what: str) -> Any:
    deadline = time.monotonic() + seconds
    while True:
        val = cond()
        if val:
            return val
        assert time.monotonic() < deadline, f"Zeitüberschreitung: {what}"
        time.sleep(0.2)


@pytest.fixture
def lab4(tmp_path_factory: pytest.TempPathFactory, xserver: Any) -> Iterator[Lab]:  # noqa: F811
    lab = Lab(tmp_path_factory.mktemp("e4"))
    lab.env.pop("ARIADNE_WEB")  # Web-Server auf freiem Port
    lab.env["DISPLAY"] = xserver.display  # Terminal und Daemon in derselben grafischen Sitzung
    lab.port = free_port()  # type: ignore[attr-defined]
    lab.paths.config_dir.mkdir(parents=True, exist_ok=True)
    lab.paths.config_file.write_text(f"[ui]\nport = {lab.port}\n")  # type: ignore[attr-defined]
    try:
        yield lab
    finally:
        lab.close_terminals()
        lab.stop_daemon()


@pytest.mark.e2e
@pytest.mark.pty
@pytest.mark.web
@pytest.mark.skipif(shutil.which("zsh") is None, reason="zsh fehlt")
def test_etappe4_user_run(lab4: Lab, xserver: Any) -> None:  # noqa: F811
    from pyrage import decrypt, x25519

    lab = lab4
    port: int = lab.port  # type: ignore[attr-defined]
    ident = x25519.Identity.generate()
    win = Window(xserver.display, x=40, y=40, w=320, h=200, rgb=(20, 120, 60), title="QTerminal")
    ollama = FakeOllama()
    try:
        lab.tools(
            (GOLDEN / "nmap.xml" / "ms2_sv_sc" / "input.xml").read_bytes(),
            (GOLDEN / "nmap.text" / "ms2_sv_sc" / "input.txt").read_bytes(),
            target=TARGET,
            lhost=KALI_IP,
        )
        lab.setup()
        rec = lab.paths.config_dir / "backup-recipients.txt"
        rec.write_text(f"# Mac\n{ident.to_public()}\n")
        rec.chmod(0o600)

        # ---- KI einrichten: lokaler Anbieter (Fake-Ollama auf Loopback) -------------------------
        (lab.paths.config_dir / "ai.toml").write_text(f"[local]\nport = {ollama.port}\n")
        out = lab.cli("ai", "setup", "--provider", "local", "--model", "test-model", "--limit", "5")
        assert "Einstellungen gespeichert" in out, out
        assert f"port = {ollama.port}" in (lab.paths.config_dir / "ai.toml").read_text()

        # ---- Session beginnen, im Terminal arbeiten, F12 s -------------------------------------
        out = lab.cli("start", "ms2", "--target", NET, "--preroll", "no", secret=PASSPHRASE)
        assert "Projekt ms2 angelegt" in out and "Aufnahme läuft" in out, out
        t = lab.terminal()
        expect_title(t, rb"\[REC ms2\]")
        run_cmd(t, "cd ~/ariadne/ms2")
        assert "vsftpd 2.3.4" in run_cmd(t, f"nmap -sV -sC -oA scans/ms2 {TARGET}")
        hotkey(t, b"s")
        expect_title(t, rb"Screenshot gespeichert", timeout=30)

        # ---- Dashboard: Anmeldung, Auswertung abwarten --------------------------------------------
        b = Browser(f"http://127.0.0.1:{port}", port)
        _ui_login(lab, b)
        st = b.ok("/api/v1/status")
        pid = st["project"]["id"]
        assert st["llm"]["mode"] == "local" and st["llm"]["model"] == "test-model" and st["llm"]["available"]
        P = f"/api/v1/p/{pid}"
        _until(lambda: _host(b.ok(f"{P}/graph"), TARGET), 60, "Host aus nmap auf der Karte")

        # ---- Screenshots: F12 s und aus dem Dashboard ----------------------------------------------
        r = b.post(f"{P}/screenshots", {"mode": "monitor", "delay_s": 0, "note": "Übersicht"})
        assert r.status_code == 201, r.text
        shots = b.ok(f"{P}/screenshots")["items"]
        assert {s["trigger"] for s in shots} == {"hotkey", "webui"}, shots
        img = b.get(f"{P}/blobs/{shots[0]['blob_id']}")
        assert img.status_code == 200 and img.content.startswith(PNG)
        assert img.headers["x-content-type-options"] == "nosniff"

        # ---- KI-Denkanstoss aus dem Dashboard ------------------------------------------------------
        ai = b.ok(f"{P}/ai/status")
        assert ai["ready"] is True and ai["provider"] == "local", ai
        r = b.post(f"{P}/ai/denkanstoss", {})
        assert r.status_code == 202, r.text
        job_id = r.json()["job"]["job_id"]
        job = _until(
            lambda: (j := b.ok(f"{P}/ai/jobs/{job_id}")["job"])["status"] not in ("queued", "running") and j,
            60,
            "KI-Auftrag",
        )
        assert job["status"] == "done" and job["created"] == 1 and job["error"] is None, job
        assert len(ollama.requests) == 1 and PASSPHRASE.encode() not in ollama.requests[0]
        sug = _until(
            lambda: [s for s in b.ok(f"{P}/next")["suggestions"] if s["origin"] == "ai"], 30, "KI in /next"
        )
        assert sug[0]["ai"]["model"] == "test-model" and sug[0]["ai"]["confirmed_if"]

        # KI-Denkanstoss als bestätigt erledigen (POST /decisions wie die Karte D3)
        r = b.post(
            f"{P}/decisions",
            {
                "decisions": [
                    {
                        "kind": "d.suggestion.done",
                        "payload": {"suggestion_key": sug[0]["suggestion_key"], "basis": sug[0]["basis"]},
                    }
                ]
            },
        )
        assert r.status_code == 201, r.text

        # ---- Finding --------------------------------------------------------------------------------
        r = b.post(
            f"{P}/decisions",
            {
                "decisions": [
                    {
                        "kind": "d.finding.create",
                        "payload": {
                            "title": FINDING,
                            "severity": "critical",
                            "status": "draft",
                            "remediation": "Dienst aktualisieren.",
                            "cves": [{"id": "CVE-2011-2523"}],
                        },
                    }
                ]
            },
        )
        assert r.status_code == 201, r.text
        _until(lambda: b.ok(f"{P}/findings")["findings"], 30, "Finding in der Liste")

        # ---- Phase eines Befehls korrigieren ----------------------------------------------------
        ph = b.ok(f"{P}/exports/phases", template="cys")
        nmap = next(c for c in ph["commands"] if c["command"].startswith("nmap"))
        r = b.post(f"{P}/exports/phases", {"template": "cys", "cmd_id": nmap["cmd_id"], "phase": "recon"})
        assert r.status_code == 200, r.text
        _until(
            lambda: any(
                c["cmd_id"] == nmap["cmd_id"] and c["source"] == "decision" and c["phase"] == "recon"
                for c in b.ok(f"{P}/exports/phases", template="cys")["commands"]
            ),
            30,
            "Phase korrigiert",
        )

        # ---- Export cys und htb -----------------------------------------------------------------------
        project_dir = lab.home / "ariadne" / "ms2"
        for template in ("cys", "htb"):
            r = b.post(f"{P}/exports", {"template": template})
            assert r.status_code == 202, r.text
            listing = _until(
                lambda tpl=template: (
                    (x := b.ok(f"{P}/exports"))["running"] is None
                    and any(e["template"] == tpl for e in x["exports"])
                    and x
                ),
                90,
                f"Export {template}",
            )
            assert listing["last_error"] is None, listing
            entry = next(e for e in listing["exports"] if e["template"] == template)
            out_dir = project_dir / entry["path"]
            manifest = json.loads((out_dir / "_ariadne" / "manifest.json").read_text())
            assert manifest and (out_dir / "00 Übersicht.md").is_file()
            findings_md = (out_dir / "03 Findings.md").read_text()
            assert "vsftpd 2" in findings_md and "Hintertür" in findings_md
            assert list((out_dir / "Belege" / "img").glob("*.png")), "Screenshots fehlen im Export"
            text = "\n".join(p.read_text("utf-8", "replace") for p in out_dir.rglob("*.md"))
            assert PASSPHRASE not in text
            if template == "cys":
                writeup = (out_dir / "02 Writeup.md").read_text()
                recon = writeup.split("Reconnaissance", 1)[1].split("Scanning und Enumeration", 1)[0]
                assert "nmap" in recon, "korrigierte Phase fehlt im Writeup"

        # ---- stop, Sicherung -------------------------------------------------------------------------
        out = lab.cli("stop")
        assert "Projekt ms2 beendet" in out, out
        target = lab.base / "abgabe" / "ms2.age"
        target.parent.mkdir()
        lab.cli("backup", "--to-file", str(target), "--project", "ms2")
        inner = decrypt(target.read_bytes(), [ident])
        with tarfile.open(fileobj=io.BytesIO(inner), mode="r|") as tar:
            names = [m.name for m in tar]
        assert names[0] == "ariadne-backup.json" and any(n.startswith("projects/ms2/.vault/") for n in names)
        assert lab.stop_daemon() == 0
    finally:
        ollama.close()
        win.close()
