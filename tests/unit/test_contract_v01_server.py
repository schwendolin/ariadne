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
    assert set(core.NOTIFY_KINDS) == {"terminal", "project", "unlocked", "locked", "presentation", "stopping"}
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
    args = parser.parse_args(["remote", "serve"])
    assert args.rcmd == "serve"
    assert parser.parse_args(["show", "inputs", "--reveal", "12"]).reveal == 12


def test_e104_fields():
    assert P.INPUT_NOECHO == 0x02 and P.INPUT_PASTE == 0x01
    h = {"terminal_id": "t", "stream_off": 0, "out_end": 0, "length": 1, "t_shim_ns": 1, "no_echo": True}
    assert events.validate_header("term.input", h)["no_echo"] is True
    assert inputs.MASK == "••••••••"
    assert _params(inputs.collect_inputs)[:1] == ["journal"]
