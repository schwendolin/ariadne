"""Parser ausführen: im Prozess (Tests) oder im Worker ohne Schlüssel (Architektur 9.2, 9.3).

:class:`SubprocessRunner` startet pro Einheit ``python -I -B -m ariadne.ingest.worker``

* mit minimalem Environment (nur ``PATH``), ohne geerbte fds (``close_fds``),
  Arbeitsordner ``/``, ohne Schlüssel;
* mit ``rlimit`` (Adressraum 1 GiB, CPU 30 s, Dateigrösse 0, Core 0, NOFILE 64)
  und ``PR_SET_NO_NEW_PRIVS``. Im ``preexec`` nur, solange der Daemon keine
  weiteren Threads hat (sonst ist ``preexec_fn`` nicht sicher); der Worker setzt
  dieselben Grenzen zusätzlich selbst, bevor er Daten liest;
* Einheit als JSON über stdin, Ergebnisse als JSON-Lines über stdout mit
  Grössenlimit, Gesamtzeit 60 s.

``match()`` läuft ebenfalls im Worker, denn auch das liest Zieldaten. Jedes
Ergebnis wird im Kern gegen das Obs/Mention-Format geprüft
(:func:`validate_item`). Absturz, Zeitüberschreitung oder ungültige Ausgabe
ergeben ein :class:`RunResult` mit ``error``, nie eine Ausnahme im Daemon.
"""

from __future__ import annotations

import contextlib
import ctypes
import json
import math
import os
import re
import selectors
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from ariadne.ingest.units import Unit
from ariadne.parsers.api import Mention, Obs, Parser, Ref, Span

__all__ = [
    "RunResult",
    "Runner",
    "InProcessRunner",
    "SubprocessRunner",
    "validate_item",
    "item_from_dict",
    "parser_factory",
    "match_and_order",
    "MAX_ITEMS",
]

MAX_ITEMS = 200_000
MAX_STR = 65_536
_PRED = re.compile(r"[a-z][a-z0-9_]{0,31}(?:\.[a-z0-9_]{1,32}){0,4}")
_VTYPE = re.compile(r"[a-z0-9_.:-]{1,32}")
_PR_SET_NO_NEW_PRIVS = 38
try:  # im Elternprozess laden, im Kind nur noch aufrufen
    _LIBC: Any = ctypes.CDLL(None, use_errno=True)
except OSError:  # pragma: no cover
    _LIBC = None


class ItemError(ValueError):
    pass


@dataclass
class RunResult:
    parser_id: str
    parser_version: str
    priority: int = 0
    items: list[Obs | Mention] = field(default_factory=list)
    error: str | None = None


class Runner(Protocol):
    def run(self, unit: Unit, parsers: Sequence[Parser]) -> list[RunResult]: ...


# --------------------------------------------------------------------------- Prüfung


def _str(v: Any, limit: int, what: str) -> str:
    if not isinstance(v, str) or not v or len(v) > limit:
        raise ItemError(what)
    return v


def _nonneg(v: Any, what: str) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ItemError(what)
    return v


def _span(d: Any, n_lines: int) -> Span:
    if not isinstance(d, Mapping):
        raise ItemError("span")
    ls, le = _nonneg(d.get("line_start"), "line_start"), _nonneg(d.get("line_end"), "line_end")
    if le < ls or (n_lines > 0 and le >= n_lines):
        raise ItemError("span ausserhalb der Einheit")
    cs, ce = d.get("col_start"), d.get("col_end")
    cs = None if cs is None else _nonneg(cs, "col_start")
    ce = None if ce is None else _nonneg(ce, "col_end")
    path = d.get("path")
    if path is not None:
        path = _str(path, 1024, "path")
    if set(d) - {"line_start", "line_end", "col_start", "col_end", "path"}:
        raise ItemError("span: unbekannte Felder")
    return Span(ls, le, cs, ce, path)


def _attrs(d: Any) -> dict[str, str]:
    if d is None:
        return {}
    if not isinstance(d, Mapping) or len(d) > 32:
        raise ItemError("attrs")
    out: dict[str, str] = {}
    for k, v in d.items():
        if not isinstance(k, str) or not 0 < len(k) <= 64 or not isinstance(v, str) or len(v) > 4096:
            raise ItemError("attrs")
        out[k] = v
    return out


def validate_item(d: Any, n_lines: int) -> dict[str, Any]:
    """Prüft ein serialisiertes Obs/Mention-Dict (Form von ``to_dict``) und gibt es zurück."""
    if not isinstance(d, Mapping):
        raise ItemError("kein Objekt")
    if "predicate" in d:
        if set(d) - {"subject", "predicate", "value", "span", "confidence", "attrs"}:
            raise ItemError("Obs: unbekannte Felder")
        _str(d.get("subject"), 2048, "subject")
        pred = _str(d.get("predicate"), 128, "predicate")
        if not _PRED.fullmatch(pred):
            raise ItemError("predicate")
        v = d.get("value")
        if isinstance(v, Mapping):
            if set(v) != {"ref"}:
                raise ItemError("value")
            _str(v.get("ref"), 2048, "value.ref")
        elif isinstance(v, str):
            if len(v) > MAX_STR:
                raise ItemError("value zu lang")
        elif not isinstance(v, int):  # bool ist int
            raise ItemError("value")
        conf = d.get("confidence")
        if conf is not None:
            if isinstance(conf, bool) or not isinstance(conf, int | float) or not math.isfinite(conf) \
                    or not 0.0 <= float(conf) <= 1.0:
                raise ItemError("confidence")
        _span(d.get("span"), n_lines)
        _attrs(d.get("attrs"))
        return dict(d)
    if "value_type" in d:
        if set(d) - {"value_type", "value", "span", "attrs"}:
            raise ItemError("Mention: unbekannte Felder")
        if not _VTYPE.fullmatch(_str(d.get("value_type"), 32, "value_type")):
            raise ItemError("value_type")
        v = d.get("value")
        if not isinstance(v, str) or len(v) > MAX_STR:
            raise ItemError("value")
        _span(d.get("span"), n_lines)
        _attrs(d.get("attrs"))
        return dict(d)
    raise ItemError("weder Obs noch Mention")


def item_from_dict(d: Mapping[str, Any], n_lines: int = 0) -> Obs | Mention:
    """Geprüftes Dict wieder als ``Obs`` bzw. ``Mention``."""
    validate_item(d, n_lines)
    span = _span(d["span"], n_lines)
    attrs = _attrs(d.get("attrs"))
    if "predicate" in d:
        v = d["value"]
        value = Ref(v["ref"]) if isinstance(v, Mapping) else v
        conf = d.get("confidence")
        return Obs(Ref(d["subject"]), d["predicate"], value, span,
                   None if conf is None else float(conf), attrs)
    return Mention(d["value_type"], d["value"], span, attrs)


# --------------------------------------------------------------------------- im Prozess


def parser_factory(p: Any) -> str:
    """``modul:Klasse`` eines Parsers, damit der Worker ihn selbst erzeugen kann."""
    cls = p if isinstance(p, type) else type(p)
    return f"{cls.__module__}:{cls.__qualname__}"


def match_and_order(unit: Any, parsers: Sequence[Any],
                    on_error: Callable[[Any, str], None]) -> list[tuple[int, Any]]:
    """Passende Parser, höchste Priorität zuerst (bei Gleichstand Reihenfolge der Registry)."""
    matched: list[tuple[int, int, Any]] = []
    for order, p in enumerate(parsers):
        try:
            prio = p.match(unit)
            prio = int(prio) if isinstance(prio, int | bool) else 0
        except Exception as exc:  # noqa: BLE001 - Parserfehler werden Ergebnis, nie Absturz
            on_error(p, f"match:{type(exc).__name__}")
            continue
        if prio > 0:
            matched.append((-prio, order, p))
    matched.sort(key=lambda x: (x[0], x[1]))
    return [(-neg, p) for neg, _, p in matched]


class InProcessRunner:
    """Führt Parser im eigenen Prozess aus (nur für Tests und Werkzeuge ohne Schlüssel)."""

    def run(self, unit: Unit, parsers: Sequence[Parser]) -> list[RunResult]:
        out: list[RunResult] = []

        def fail(p: Any, reason: str) -> None:
            out.append(RunResult(str(p.id), str(p.version), 0, [], reason))

        n_lines = len(unit.lines)
        for prio, p in match_and_order(unit, parsers, fail):
            res = RunResult(str(p.id), str(p.version), prio)
            try:
                for k, item in enumerate(p.parse(unit)):
                    if k >= MAX_ITEMS:
                        raise ItemError("zu viele Ergebnisse")
                    d = json.loads(json.dumps(item.to_dict()))
                    res.items.append(item_from_dict(d, n_lines))
            except ItemError as exc:
                res.items, res.error = [], f"invalid:{exc}"
            except Exception as exc:  # noqa: BLE001
                res.items, res.error = [], f"crash:{type(exc).__name__}"
            out.append(res)
        return out


# --------------------------------------------------------------------------- Subprozess


class _Abort(Exception):
    pass


def _limits(mem: int, cpu: int) -> Callable[[], None]:
    def apply() -> None:
        import resource

        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        if _LIBC is not None:
            _LIBC.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

    return apply


class SubprocessRunner:
    """Startet pro Einheit einen Worker-Prozess (Architektur 9.3, v0.1)."""

    def __init__(self, *, timeout: float = 60.0, mem_limit: int = 1 << 30, cpu_limit: int = 30,
                 max_output: int = 64 << 20, max_line: int = 4 << 20, max_input: int = 96 << 20,
                 python: str | None = None, extra_paths: Iterable[str] = (),
                 allowed_prefixes: Iterable[str] = ("ariadne.parsers.",),
                 trust_registry: bool = True) -> None:
        """``allowed_prefixes``: Module, die der Worker laden darf. Mit ``trust_registry``
        zusätzlich genau die Module der übergebenen Parser (Registry und Plugin-Allowlist
        des Daemons sind vertrauenswürdig)."""
        self.timeout = timeout
        self.mem_limit = mem_limit
        self.cpu_limit = cpu_limit
        self.max_output = max_output
        self.max_line = max_line
        self.max_input = max_input
        self.python = python or sys.executable
        self.extra_paths = [str(p) for p in extra_paths]
        self.allowed_prefixes = tuple(allowed_prefixes)
        self.trust_registry = trust_registry

    def run(self, unit: Unit, parsers: Sequence[Parser]) -> list[RunResult]:
        specs = [{"id": str(p.id), "version": str(p.version), "factory": parser_factory(p)} for p in parsers]
        if not specs:
            return []
        n_lines = len(unit.lines)
        allowed = list(self.allowed_prefixes)
        if self.trust_registry:
            allowed += sorted({s["factory"].split(":", 1)[0] for s in specs})
        req = {"unit": unit.to_dict(), "parsers": specs, "paths": self.extra_paths, "allowed": allowed}
        payload = json.dumps(req, ensure_ascii=False, separators=(",", ":")).encode()
        if len(payload) > self.max_input:
            return [RunResult(s["id"], s["version"], 0, [], "too_large") for s in specs]
        try:
            lines, reason = self._spawn(payload)
        except OSError:
            lines, reason = [], "spawn_failed"
        return self._collect(specs, lines, reason, n_lines)

    # ------------------------------------------------------------------ #
    def _spawn(self, payload: bytes) -> tuple[list[bytes], str | None]:
        argv = [self.python, "-I", "-B", "-m", "ariadne.ingest.worker",
                "--mem", str(self.mem_limit), "--cpu", str(self.cpu_limit)]
        env = {"PATH": os.environ.get("PATH") or os.defpath}
        preexec = _limits(self.mem_limit, self.cpu_limit) if threading.active_count() == 1 else None
        proc = subprocess.Popen(  # noqa: S603 - fester Interpreter, keine Shell
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
            close_fds=True, cwd="/", preexec_fn=preexec,
        )
        deadline = time.monotonic() + self.timeout
        try:
            lines = self._communicate(proc, payload, deadline)
            reason = None
            try:
                rc = proc.wait(timeout=max(0.1, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise _Abort("timeout") from None
            if rc != 0:
                reason = "killed" if rc < 0 else f"exit:{rc}"
            return lines, reason
        except _Abort as exc:
            with contextlib.suppress(OSError):
                proc.kill()
            proc.wait()
            return [], str(exc)
        finally:
            for f in (proc.stdin, proc.stdout):
                if f is not None:
                    with contextlib.suppress(OSError):
                        f.close()

    def _communicate(self, proc: subprocess.Popen[bytes], payload: bytes, deadline: float) -> list[bytes]:
        assert proc.stdin is not None and proc.stdout is not None
        sel = selectors.DefaultSelector()
        win, rout = proc.stdin.fileno(), proc.stdout.fileno()
        os.set_blocking(win, False)
        view = memoryview(payload)
        written = 0
        sel.register(win, selectors.EVENT_WRITE)
        sel.register(rout, selectors.EVENT_READ)
        buf = bytearray()
        lines: list[bytes] = []
        total = 0
        try:
            while sel.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _Abort("timeout")
                for key, _ in sel.select(remaining):
                    if key.fd == win:
                        try:
                            written += os.write(win, view[written : written + 65536])
                        except BlockingIOError:
                            continue
                        except (BrokenPipeError, OSError):
                            written = len(payload)
                        if written >= len(payload):
                            sel.unregister(win)
                            proc.stdin.close()
                        continue
                    chunk = os.read(rout, 65536)
                    if not chunk:
                        sel.unregister(rout)
                        continue
                    total += len(chunk)
                    if total > self.max_output:
                        raise _Abort("output_too_large")
                    buf += chunk
                    while True:
                        nl = buf.find(b"\n")
                        if nl < 0:
                            break
                        lines.append(bytes(buf[:nl]))
                        del buf[: nl + 1]
                    if len(buf) > self.max_line:
                        raise _Abort("line_too_large")
        finally:
            sel.close()
        if buf.strip():
            lines.append(bytes(buf))
        return lines

    def _collect(self, specs: list[dict[str, str]], lines: list[bytes], reason: str | None,
                 n_lines: int) -> list[RunResult]:
        by_id = {s["id"]: s for s in specs}
        results: dict[str, RunResult] = {}
        order: list[str] = []
        done: set[str] = set()
        for raw in lines:
            try:
                msg = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                reason = reason or "bad_output"
                break
            if not isinstance(msg, dict) or msg.get("p") not in by_id:
                reason = reason or "bad_output"
                break
            pid = msg["p"]
            res = results.get(pid)
            if res is None:
                res = results[pid] = RunResult(pid, by_id[pid]["version"])
                order.append(pid)
            if pid in done:
                continue
            t = msg.get("t")
            if t == "match":
                prio = msg.get("prio")
                res.priority = prio if isinstance(prio, int) and not isinstance(prio, bool) else 0
            elif t == "item":
                if len(res.items) >= MAX_ITEMS:
                    res.items, res.error = [], "invalid:zu viele Ergebnisse"
                    done.add(pid)
                    continue
                try:
                    res.items.append(item_from_dict(msg.get("d"), n_lines))
                except (ItemError, KeyError, TypeError) as exc:
                    res.items, res.error = [], f"invalid:{exc}"
                    done.add(pid)
            elif t == "done":
                done.add(pid)
            elif t == "error":
                e = msg.get("e")
                res.items, res.error = [], e if isinstance(e, str) and len(e) < 200 else "crash"
                done.add(pid)
        out: list[RunResult] = []
        for pid in order:
            res = results[pid]
            if pid not in done:
                res.items, res.error = [], reason or "incomplete"
            out.append(res)
        if reason is not None and not order:
            # Worker starb vor jeder Ausgabe: alle Parser gelten als fehlgeschlagen
            out = [RunResult(s["id"], s["version"], 0, [], reason) for s in specs]
        return out
