"""Vertragstests für den Bau v0.1-Server (Phase 1): Schnittstellen, auf die sich die Teile
«server», «api», «backup» und «remote» verlassen. Geprüft werden nur Formen (Namen,
Signaturen, Felder), nie das Verhalten der Stubs. Diese Datei gehört keinem Bau-Agenten;
Änderungen nur additiv.
"""

from __future__ import annotations

import argparse
import inspect

from ariadne import events
from ariadne._shim import protocol as P
from ariadne.backup import api as backup_api
from ariadne.backup import reminder
from ariadne.cli import backup as backup_cli
from ariadne.cli import main as cli_main
from ariadne.cli import remote as remote_cli
from ariadne.cli import ui as ui_cli
from ariadne.daemon import core, extensions
from ariadne.daemon.ingest import IngestService
from ariadne.ingest import inputs
from ariadne.remote import check as remote_check
from ariadne.remote import serve as remote_serve
from ariadne.web import api as web_api
from ariadne.web import ctx as web_ctx
from ariadne.web.integration import WebExtension


def _params(fn) -> list[str]:
    return list(inspect.signature(fn).parameters)


def test_daemon_extension_points():
    assert _params(core.Daemon.add_listener) == ["self", "fn"]
    assert _params(core.Daemon.add_ops) == ["self", "ops"]
    assert "extensions" in _params(core.Daemon.__init__)
    assert set(core.NOTIFY_KINDS) == {"terminal", "project", "unlocked", "locked", "presentation", "stopping",
                                      "job", "scope"}  # «scope» additiv (E129)
    assert _params(core.Daemon.remove_listener) == ["self", "fn"]
    assert _params(IngestService.remove_listener) == ["self", "fn"]
    assert core.ctl_peer_pid() is None  # ausserhalb einer ctl-Operation
    for op in ("presentation", "unlock", "lock", "status", "terminals", "term.pause", "term.resume",
               "ctx.set", "ctx.push", "ctx.pop", "keystep.mark", "preroll.info", "stop"):
        assert op in core._OPS
    for op in ("show", "search", "claim.confirm", "claim.reject", "unit.distrust", "reparse", "input.reveal"):
        assert op in core._OPS
    assert inspect.iscoroutinefunction(IngestService.query_journal)


def test_web_shared_interface():
    s = web_ctx.SessionInfo("s1", "sshd", 1, 2, 3, "sshd-session")
    assert s.origin == "sshd" and not hasattr(s, "token")
    assert set(web_ctx.SSE_EVENTS) >= {"changes", "terminal", "inbox", "project", "reset", "presentation",
                                       "progress"}
    assert _params(web_api.register) == ["app", "ctx"]
    assert _params(web_api.attach_sources) == ["ctx"]
    ext = WebExtension.__new__(WebExtension)
    assert WebExtension.name == "web" and inspect.iscoroutinefunction(ext.start)
    assert inspect.iscoroutinefunction(ext.stop)
    assert callable(extensions.default_extensions)


def test_backup_and_remote_interfaces():
    assert _params(backup_api.backup_to_stream)[:2] == ["out", "paths"]
    assert _params(backup_api.restore_from_stream) == ["inp", "paths"]
    assert issubclass(backup_api.BackupError, RuntimeError)
    assert _params(reminder.after_stop_lines) == ["paths", "stop_result"]
    assert _params(remote_serve.main) == ["paths", "env"]
    assert remote_serve.ALLOWED == ("code", "unlock", "lock", "revoke", "backup", "restore", "check")
    assert _params(remote_check.run_checks)[:1] == ["paths"] and callable(remote_check.quick_ok)


def test_cli_commands_are_registered_by_their_owners():
    parser = cli_main.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    for name in ("ui", "backup", "restore", "remote", "unlock", "start", "show"):
        assert name in sub.choices
    for mod in (ui_cli, backup_cli, remote_cli):
        assert _params(mod.register) == ["sub"]
    args = parser.parse_args(["ui", "--revoke"])
    assert args.revoke == "all"
    args = parser.parse_args(["backup", "--to-file", "x.age"])
    assert args.to_file == "x.age"
    args = parser.parse_args(["restore", "--from-file", "x", "--no-verify"])
    assert args.from_file == "x" and args.no_verify is True
    args = parser.parse_args(["remote", "serve"])
    assert args.rcmd == "serve"
    assert parser.parse_args(["show", "inputs", "--reveal", "12"]).reveal == 12


def test_e104_fields():
    assert P.INPUT_NOECHO == 0x02 and P.INPUT_PASTE == 0x01
    h = {"terminal_id": "t", "stream_off": 0, "out_end": 0, "length": 1, "t_shim_ns": 1, "no_echo": True}
    assert events.validate_header("term.input", h)["no_echo"] is True
    assert inputs.MASK == "••••••••"
    assert _params(inputs.collect_inputs)[:1] == ["journal"]


def test_server_part_interfaces():
    """Teil «server» (additiv): kein Stub mehr, Schnittstellen aus Vertrag 3.1 bis 3.4."""
    from ariadne.web import app as web_app
    from ariadne.web import integration, sse
    from ariadne.web.sessions import SessionStore

    assert integration.STUB is False
    assert _params(web_app.build_app)[:3] == ["ctx", "sessions", "bus"]
    assert callable(sse.EventBus().publish)
    assert {"exchange", "authenticate", "revoke", "listing", "issue_code"} <= set(dir(SessionStore))
    assert _params(ui_cli.cmd_ui) == ["paths", "args"]
    ns = cli_main.build_parser().parse_args(["ui", "--revoke", "ab12cd34"])
    assert ns.revoke == "ab12cd34" and ns.fn is ui_cli.cmd_ui


def test_api_part_routes_and_schema():
    """Teil «api» (additiv): kein Stub mehr; alle Routen [v0.1] und [501] aus docs/web-api.md sind
    angemeldet, nur unter ``/api/v1``, ohne die Routen des Servers; das Schema lässt sich erzeugen."""
    from fastapi import FastAPI

    from ariadne.web.api.common import ALLOWED_OPS

    assert web_api.STUB is False
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    web_api.register(app, web_ctx.WebContext(object(), None))
    paths = {p: {m.upper() for m in ops} for p, ops in app.openapi()["paths"].items()}
    want = {
        "/status": {"GET"}, "/terminals": {"GET"}, "/terminals/{tid}/pause": {"POST"},
        "/terminals/{tid}/resume": {"POST"}, "/terminals/{tid}/context": {"POST"}, "/presentation": {"PUT"},
        "/p/{pid}/project": {"GET"}, "/p/{pid}/graph": {"GET"}, "/p/{pid}/changes": {"GET"},
        "/p/{pid}/ui/positions": {"GET", "PUT"}, "/p/{pid}/hosts": {"GET"},
        "/p/{pid}/hosts/{host_id}": {"GET"},
        "/p/{pid}/services": {"GET"}, "/p/{pid}/next": {"GET"}, "/p/{pid}/timeline": {"GET"},
        "/p/{pid}/inputs": {"GET"}, "/p/{pid}/facts/{claim_key}/sources": {"GET"},
        "/p/{pid}/units/{unit_id}": {"GET"}, "/p/{pid}/units/{unit_id}/lines": {"GET"},
        "/p/{pid}/units/{unit_id}/log.txt": {"GET"}, "/p/{pid}/decisions": {"POST"},
        "/p/{pid}/decisions/confirm-group": {"POST"}, "/p/{pid}/search": {"GET"},
        "/p/{pid}/files/pending": {"GET"}, "/p/{pid}/secrets/reveal": {"POST"},
        "/p/{pid}/ai/denkanstoss": {"POST"}, "/p/{pid}/credentials": {"GET"}, "/p/{pid}/cred-matrix": {"GET"},
        "/p/{pid}/blobs/{blob_id}": {"GET"}, "/p/{pid}/exports": {"GET", "POST"},
        "/p/{pid}/findings": {"GET"},
    }
    for path, methods in want.items():
        assert methods <= paths.get("/api/v1" + path, set()), path
    assert all(p.startswith("/api/v1/") for p in paths)
    assert "/api/v1/session" not in paths and "/api/v1/events" not in paths
    assert not ALLOWED_OPS & {"unlock", "start", "init", "lock", "stop", "shutdown", "redact", "import",
                              "reparse", "verify", "secrets.add", "project.open", "ui.code"}
    assert callable(web_api.attach_sources)


def test_backup_part_interfaces():
    """Teil «backup» (additiv): echte Umsetzung, Zusatzparameter nur als Schlüsselwörter."""
    from ariadne.backup import model as backup_model

    assert backup_api.STUB is False
    sig = inspect.signature(backup_api.backup_to_stream)
    for name in ("projects", "target", "target_path"):
        assert sig.parameters[name].kind is inspect.Parameter.KEYWORD_ONLY
    for code in ("no_recipients", "tty_refused", "project_open", "vault_exists", "project_exists",
                 "bad_manifest", "version", "hash_mismatch", "io"):
        assert code in backup_model.CODES
    assert backup_api.RestoreResult(("a",), True).verified == {}
    assert callable(backup_api.backup_summary_lines) and callable(backup_api.restore_summary_lines)
    args = cli_main.build_parser().parse_args(["restore", "--identity", "-", "--passphrase-fd", "3"])
    assert args.identity == "-" and args.passphrase_fd == 3


def test_remote_part_interfaces():
    """Teil «remote» (additiv): kein Stub mehr; Forced Command, Schnellprüfung und Skripte."""
    from pathlib import Path

    assert remote_serve.STUB is False and remote_check.STUB is False
    assert remote_serve.parse_command("code") == "code" and remote_serve.parse_command("code; id") is None
    assert callable(remote_serve.HOLD) and _params(remote_serve.hold)[:1] == ["ppid"]
    assert _params(remote_check.quick_ok)[:1] == ["paths"]
    assert _params(remote_check.quick_checks)[:1] == ["paths"]
    assert remote_check.SETUP_ROOT_ENV == "ARIADNE_SETUP_ROOT"
    assert _params(remote_cli.ensure_runtime_dir)[:1] == ["env"]
    root = Path(__file__).resolve().parents[2]
    for rel in ("packaging/smartlearn/kali-setup.sh", "packaging/mac/ariadne-mac",
                "docs/anleitung-fernzugriff.md"):
        assert (root / rel).is_file(), rel
    assert cli_main.build_parser().parse_args(["remote", "check", "--full"]).full is True


def test_integration_additions():
    """Nachträge der Integration (contract_requests der Teile, E115): nur additiv."""
    import inspect

    from ariadne.ingest import queries
    from ariadne.store.journal import JournalReader, SqlCipherJournal
    from ariadne.web import security

    assert callable(queries.sort_time) and callable(queries.boot_ranks)
    for cls in (JournalReader, SqlCipherJournal):
        assert callable(cls.read_head) and callable(cls.get_by_id)
    assert list(inspect.signature(security.shell_navigation).parameters) == ["method", "path", "headers"]
    nav = {b"sec-fetch-site": [b"cross-site"], b"sec-fetch-mode": [b"navigate"],
           b"sec-fetch-dest": [b"document"]}
    assert security.shell_navigation("GET", "/", nav)
    assert not security.shell_navigation("GET", "/api/v1/x", nav)
    assert not security.shell_navigation("POST", "/", nav)
