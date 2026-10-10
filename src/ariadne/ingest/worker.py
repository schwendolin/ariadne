"""Worker-Prozess für Parser (Architektur 9.3, v0.1). Start: ``python -I -B -m ariadne.ingest.worker``.

Liest eine Anfrage als JSON von stdin::

    {"unit": Unit.to_dict(), "parsers": [{"id", "version", "factory": "modul:Klasse"}],
     "paths": [...], "allowed": ["ariadne.parsers.", "exaktes.modul"]}

und schreibt JSON-Lines nach stdout, pro passendem Parser (höchste Priorität
zuerst)::

    {"t": "match", "p": id, "prio": n}
    {"t": "item", "p": id, "d": <Obs/Mention.to_dict()>}   (beliebig oft)
    {"t": "done", "p": id}  oder  {"t": "error", "p": id, "e": "crash:MemoryError"}

Der Worker hält keine Schlüssel und kennt keine Datenbank. Er setzt seine
Grenzen selbst (zusätzlich zum ``preexec`` des Runners), bevor er Daten liest.
Fehlermeldungen enthalten nur Klassennamen, nie Inhalte.
"""

from __future__ import annotations

import importlib
import json
import sys
from typing import Any, BinaryIO

MAX_INPUT = 96 << 20


def _lower(res: int, value: int, hard_extra: int = 0) -> None:
    import resource

    try:
        _soft, hard = resource.getrlimit(res)
        if hard != resource.RLIM_INFINITY and hard < value + hard_extra:
            value, hard_extra = min(value, hard), max(0, hard - value)
        resource.setrlimit(res, (value, value + hard_extra))
    except (OSError, ValueError):
        pass


def _apply_limits(mem: int | None, cpu: int | None) -> None:
    """Grenzen wie im ``preexec`` des Runners; Senken ist immer erlaubt."""
    try:
        import resource
    except ImportError:  # pragma: no cover
        return
    if mem:
        _lower(resource.RLIMIT_AS, mem)
    if cpu:
        _lower(resource.RLIMIT_CPU, cpu, 1)
    _lower(resource.RLIMIT_FSIZE, 0)
    _lower(resource.RLIMIT_CORE, 0)
    _lower(resource.RLIMIT_NOFILE, 64)
    try:
        import ctypes

        ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    except (OSError, AttributeError):
        pass


def _args(argv: list[str]) -> tuple[int | None, int | None]:
    mem = cpu = None
    for i, a in enumerate(argv):
        if a == "--mem" and i + 1 < len(argv) and argv[i + 1].isdigit():
            mem = int(argv[i + 1])
        if a == "--cpu" and i + 1 < len(argv) and argv[i + 1].isdigit():
            cpu = int(argv[i + 1])
    return mem, cpu


class _Out:
    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream

    def emit(self, obj: dict[str, Any]) -> None:
        self.stream.write(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")

    def flush(self) -> None:
        self.stream.flush()


def _load(spec: dict[str, Any], allowed: tuple[str, ...]) -> Any:
    factory = spec.get("factory")
    if not isinstance(factory, str) or ":" not in factory:
        raise ImportError("factory")
    mod_name, _, qual = factory.partition(":")
    if not any(mod_name == a or (a.endswith(".") and mod_name.startswith(a)) for a in allowed):
        raise ImportError("not_allowed")
    obj: Any = importlib.import_module(mod_name)
    for part in qual.split("."):
        obj = getattr(obj, part)
    inst = obj() if isinstance(obj, type) else obj
    if str(getattr(inst, "id", "")) != spec.get("id"):
        raise ImportError("id_mismatch")
    return inst


def run(req: dict[str, Any], out: _Out) -> None:
    from ariadne.ingest.runner import match_and_order
    from ariadne.ingest.units import Unit

    for p in req.get("paths") or ():
        if isinstance(p, str) and p not in sys.path:
            sys.path.insert(0, p)
    allowed = tuple(a for a in req.get("allowed") or ("ariadne.parsers.",) if isinstance(a, str) and a)
    unit = Unit.from_dict(req["unit"])
    parsers = []
    for spec in req.get("parsers") or ():
        try:
            parsers.append(_load(spec, allowed))
        except Exception as exc:  # noqa: BLE001
            out.emit({"t": "error", "p": spec.get("id"), "e": f"load:{type(exc).__name__}:{exc}"[:120]})
    out.flush()

    def fail(p: Any, reason: str) -> None:
        out.emit({"t": "error", "p": str(p.id), "e": reason})

    ordered = match_and_order(unit, parsers, fail)
    for prio, p in ordered:
        out.emit({"t": "match", "p": str(p.id), "prio": prio})
    out.flush()
    for _prio, p in ordered:
        pid = str(p.id)
        try:
            for item in p.parse(unit):
                out.emit({"t": "item", "p": pid, "d": item.to_dict()})
            out.emit({"t": "done", "p": pid})
        except MemoryError:
            out.emit({"t": "error", "p": pid, "e": "crash:MemoryError"})
        except Exception as exc:  # noqa: BLE001 - Parserfehler werden Ergebnis
            out.emit({"t": "error", "p": pid, "e": f"crash:{type(exc).__name__}"})
        out.flush()


def main(argv: list[str] | None = None, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> int:
    mem, cpu = _args(list(sys.argv[1:] if argv is None else argv))
    if argv is None:
        _apply_limits(mem, cpu)
    src = stdin or sys.stdin.buffer
    out = _Out(stdout or sys.stdout.buffer)
    data = src.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        return 3
    try:
        req = json.loads(data)
        if not isinstance(req, dict):
            return 3
        run(req, out)
    except MemoryError:
        return 4
    except (ValueError, KeyError, TypeError):
        return 3
    out.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
