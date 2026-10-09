"""Event- und Entscheid-Katalog. Einzige Quelle für alle Journal-Einträge.

Architektur 5.3. Regeln:

* Schicht 1 (``raw``) enthält nur, was sich nicht neu berechnen lässt.
* Schicht 3 (``decision``, Präfix ``d.``) enthält Entscheide des Nutzers.
* ``system``-Events stammen vom Daemon selbst (Checkpoint, Redaktion, Zeitsprung).
* Befehle, Segmente und automatische Kontextspannen sind Schicht 2 und stehen
  nie im Journal.
* Überall genau ein Bezeichner ``terminal_id``. Die Operator-ID setzt der Daemon.
* Header sind kanonisches JSON ohne Floats (:func:`canonical_json`).

Ein neues Event braucht hier ein Modell und einen Eintrag in :data:`KINDS`.
Änderungen an bestehenden Modellen nur abwärtskompatibel oder mit neuer Version.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "Layer",
    "KindSpec",
    "KINDS",
    "canonical_json",
    "validate_header",
    "layer_of",
    "Redaction",
    "Stage",
]

Layer = Literal["raw", "decision", "system"]
Mark = Literal["A", "B", "C", "D"]
GapReason = Literal[
    "rec_off", "buffer_overflow", "daemon_down", "project_switch",
    "sensitive_output", "locked", "disk_low", "shim_error",
]
StageKind = Literal[
    "local", "su", "ssh", "winrm", "remote", "revshell", "msf", "meterpreter", "db", "unknown"
]
StageState = Literal["active", "suspended"]
StageSource = Literal["auto", "hotkey", "webui", "cli", "suggestion"]
Keystep = Literal["foothold", "privesc", "pivot", "loot"]
WorkStatus = Literal["open", "in_progress", "dead_end", "done", "out_of_scope"]
AccessLevel = Literal["none", "user", "admin"]
Origin = Literal["shim", "webui", "cli", "watcher", "gateway", "daemon", "import"]


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --------------------------------------------------------------------------- #
# Gemeinsame Bausteine
# --------------------------------------------------------------------------- #


class Redaction(_M):
    """Längenerhaltende Schwärzung eines eigenen Secrets in einem Output-Chunk.

    ``start``/``end`` sind absolute Stream-Offsets (end exklusiv).
    """

    label: str
    start: int = Field(ge=0)
    end: int = Field(ge=0)


class Stage(_M):
    """Eine Stufe im Kontext-Stapel eines Terminals (Architektur 3.5).

    ``host`` ist die eingegebene Kennung (``ip:default/10.10.10.5``,
    ``name:web01``) oder leer. Aufgelöst wird erst in der Projektion.
    """

    kind: StageKind
    host: str | None = None
    user: str | None = None
    opened_at: int = Field(ge=0, description="Stream-Offset, an dem die Stufe begann")
    state: StageState = "active"
    source: StageSource = "auto"
    candidate: str | None = Field(default=None, description="Ziel-Kandidat aus argv, unbestätigt")


# --------------------------------------------------------------------------- #
# Schicht 1: Rohereignisse
# --------------------------------------------------------------------------- #


class TermOpen(_M):
    terminal_id: str
    tty: str | None = None
    shell: str
    term: str | None = None
    rows: int = Field(ge=0)
    cols: int = Field(ge=0)
    tmux_pane: str | None = None
    window_id: str | None = None
    shim_version: str


class TermBind(_M):
    terminal_id: str
    project_id: str


class TermOut(_M):
    """Output-Chunk. Die Bytes stehen im Body, nicht im Header."""

    terminal_id: str
    stream_off: int = Field(ge=0)
    length: int = Field(ge=0)
    t_shim_ns: int
    mono_ns: int | None = None
    redactions: tuple[Redaction, ...] = ()


class TermMarkEv(_M):
    """Gültiger Shell-Marker (Nonce geprüft). Siehe Architektur 3.3.

    ``fg_shell`` sagt, ob beim Lesen die Vordergrund-Prozessgruppe die der
    Shell war. D- und A-Marker zählen nur mit ``fg_shell=True``.
    """

    terminal_id: str
    stream_off: int = Field(ge=0)
    mark: Mark
    counter: int = Field(ge=0)
    fg_shell: bool
    cmd_typed: str | None = None
    cmd_expanded: str | None = None
    cmd_vars: Mapping[str, str] | None = None
    cwd: str | None = None
    exit: int | None = None
    pipestatus: tuple[int, ...] | None = None
    shell_pid: int | None = None
    shlvl: int | None = None
    user: str | None = None


class TermResize(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    rows: int = Field(ge=0, le=1000)
    cols: int = Field(ge=0, le=1000)


class TermCtxSnapshot(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    stack: tuple[Stage, ...]


class TermGap(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    reason: GapReason
    bytes_lost: int = Field(ge=0, default=0)


class TermClose(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    exit_code: int | None = None


class TermOsc52Blocked(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    length: int = Field(ge=0)


class TermMarkerForged(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    reason: Literal["bad_nonce", "replay", "not_foreground", "malformed", "oversize"]


class RecSet(_M):
    on: bool
    source: Literal["webui", "cli", "hotkey", "system"]
    terminal_id: str | None = None


class FileObserved(_M):
    path: str = Field(description="Pfad relativ zum Projekt-Arbeitsbereich")
    sha256: str
    size: int = Field(ge=0)
    blob_id: str | None = Field(default=None, description="None, wenn nur referenziert")
    mime: str | None = None
    sniff: str | None = None
    origin: Literal["watcher", "import", "companion", "reconcile"]
    produced_by_cmd: str | None = Field(default=None, description="cmd_id, falls bekannt")
    context_terminal: str | None = None
    host_hint: str | None = Field(default=None, description="Kennung bei `ariadne import --host`")
    rec: bool = True


class ShotCaptured(_M):
    blob_id: str
    sha256: str
    mode: Literal["window", "monitor", "region"]
    backend: str
    trigger: Literal["hotkey", "cli", "webui", "keystep"]
    width: int = Field(ge=0)
    height: int = Field(ge=0)
    window_title: str | None = None
    wm_class: str | None = None
    terminal_id: str | None = None
    stream_off: int | None = None
    note: str | None = None
    rec: bool = True


class NetRoute(_M):
    cmd_id: str
    target: str
    src_ip: str | None = None
    dev: str | None = None
    via: str | None = None


class ClockCheck(_M):
    synced: bool | None = None
    ntp_server: str | None = None
    timezone: str | None = None
    detail: str | None = None


class AiCall(_M):
    call_id: str
    function: Literal["denkanstoss", "extraktion", "vision", "frage", "zusammenfassung"]
    provider: Literal["claude", "ollama"]
    model_requested: str
    model_served: str | None = None
    prompt_version: str
    status: Literal["ok", "refused", "truncated", "error", "policy", "budget", "offline"]
    refusal_category: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    cost_microusd: int | None = None
    payload_blob: str | None = None
    response_blob: str | None = None


class SystemCheckpoint(_M):
    reason: Literal["rec_off", "close", "daily", "manual"]
    head_seq: int
    head_hash: str


class SystemRedaction(_M):
    ref_seq: int
    label: str
    reason: str


class SystemClockJump(_M):
    delta_ns: int


class SystemMigration(_M):
    from_version: int
    to_version: int


class ProjectCreated(_M):
    project_id: str
    slug: str
    profile: Literal["lab", "customer"]
    schema_version: int


# --------------------------------------------------------------------------- #
# Schicht 3: Entscheide (Präfix d.)
# --------------------------------------------------------------------------- #


class DClaim(_M):
    claim_key: str
    reason: str | None = None


class DClaimEdit(_M):
    claim_key: str
    value: str


class DEntityMerge(_M):
    identifiers: tuple[str, ...] = Field(min_length=2)
    reason: str | None = None


class DEntitySplit(_M):
    identifiers: tuple[str, ...] = Field(min_length=2)
    reason: str | None = None


class DCtxSet(_M):
    """Kontext für einen Offset-Bereich setzen (auch rückwirkend)."""

    terminal_id: str
    from_off: int = Field(ge=0)
    to_off: int | None = None
    depth: int | None = Field(default=None, description="Stufe im Stapel, None = oberste")
    host: str | None = None
    user: str | None = None
    kind: StageKind | None = None


class DCtxPush(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    kind: StageKind = "unknown"
    host: str | None = None
    user: str | None = None


class DCtxPop(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)


class DCtxAccept(_M):
    terminal_id: str
    stream_off: int = Field(ge=0)
    suggestion_key: str


class DKeystepMark(_M):
    terminal_id: str | None = None
    stream_off: int | None = None
    step: Keystep
    host: str | None = None
    note: str | None = None


class DStatusWork(_M):
    subject: str = Field(description="Kennung oder Entitätsschlüssel")
    value: WorkStatus
    reason: str | None = None


class DStatusAccess(_M):
    subject: str
    value: AccessLevel


class DNoteSet(_M):
    subject: str
    text: str = Field(max_length=100_000)


class DTag(_M):
    subject: str
    tag: str = Field(max_length=64)


class DScopeUpdate(_M):
    """Vollständiger Snapshot der Projekteinstellungen als TOML."""

    version: int = Field(ge=1)
    toml: str


class DAutomodeSet(_M):
    enabled: bool
    parsers: tuple[str, ...] = ()
    auto_ctx: bool = False


class DConflictResolve(_M):
    conflict_key: str
    choice: str | None = None
    keep_open: bool = False


class DTerminalLabel(_M):
    terminal_id: str
    label: str = Field(max_length=64)


class DRevoke(_M):
    decision_id: str
    reason: str | None = None


class DSuggestion(_M):
    suggestion_key: str
    reason: str | None = None


class DLabNotCustomer(_M):
    """Bestätigung «Das ist kein Kundenauftrag» (Architektur 8.1)."""

    scope_version: int


class DGeneric(_M):
    """Platzhalter für Entscheide, deren Modell erst später kommt (Findings,
    Artefakte, Hypothesen, Prüfziele). Felder werden später typisiert."""

    model_config = ConfigDict(extra="allow", frozen=True)


# --------------------------------------------------------------------------- #
# Katalog
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class KindSpec:
    kind: str
    layer: Layer
    model: type[BaseModel]
    has_body: bool = False


def _k(kind: str, layer: Layer, model: type[BaseModel], has_body: bool = False) -> KindSpec:
    return KindSpec(kind, layer, model, has_body)


KINDS: dict[str, KindSpec] = {
    s.kind: s
    for s in [
        # Schicht 1
        _k("term.open", "raw", TermOpen),
        _k("term.bind", "raw", TermBind),
        _k("term.out", "raw", TermOut, has_body=True),
        _k("term.mark", "raw", TermMarkEv),
        _k("term.resize", "raw", TermResize),
        _k("term.ctx_snapshot", "raw", TermCtxSnapshot),
        _k("term.gap", "raw", TermGap),
        _k("term.close", "raw", TermClose),
        _k("term.osc52_blocked", "raw", TermOsc52Blocked),
        _k("term.marker_forged", "raw", TermMarkerForged),
        _k("rec.set", "raw", RecSet),
        _k("file.observed", "raw", FileObserved),
        _k("shot.captured", "raw", ShotCaptured),
        _k("net.route", "raw", NetRoute),
        _k("clock.check", "raw", ClockCheck),
        _k("ai.call", "raw", AiCall),
        # System
        _k("system.project_created", "system", ProjectCreated),
        _k("system.checkpoint", "system", SystemCheckpoint),
        _k("system.redaction", "system", SystemRedaction, has_body=True),
        _k("system.clock_jump", "system", SystemClockJump),
        _k("system.migration", "system", SystemMigration),
        # Schicht 3
        _k("d.claim.confirm", "decision", DClaim),
        _k("d.claim.reject", "decision", DClaim),
        _k("d.claim.edit", "decision", DClaimEdit),
        _k("d.entity.merge", "decision", DEntityMerge),
        _k("d.entity.split", "decision", DEntitySplit),
        _k("d.ctx.set", "decision", DCtxSet),
        _k("d.ctx.push", "decision", DCtxPush),
        _k("d.ctx.pop", "decision", DCtxPop),
        _k("d.ctx.accept", "decision", DCtxAccept),
        _k("d.keystep.mark", "decision", DKeystepMark),
        _k("d.status.work", "decision", DStatusWork),
        _k("d.status.access", "decision", DStatusAccess),
        _k("d.note.set", "decision", DNoteSet),
        _k("d.tag.add", "decision", DTag),
        _k("d.tag.remove", "decision", DTag),
        _k("d.scope.update", "decision", DScopeUpdate),
        _k("d.automode.set", "decision", DAutomodeSet),
        _k("d.conflict.resolve", "decision", DConflictResolve),
        _k("d.terminal.label", "decision", DTerminalLabel),
        _k("d.revoke", "decision", DRevoke),
        _k("d.suggestion.done", "decision", DSuggestion),
        _k("d.suggestion.dismiss", "decision", DSuggestion),
        _k("d.lab.not_customer", "decision", DLabNotCustomer),
        _k("d.finding", "decision", DGeneric),
        _k("d.artifact", "decision", DGeneric),
        _k("d.hypothesis", "decision", DGeneric),
        _k("d.goal.status", "decision", DGeneric),
    ]
}


def layer_of(kind: str) -> Layer:
    try:
        return KINDS[kind].layer
    except KeyError as exc:
        raise ValueError(f"unbekannte Event-Art: {kind!r}") from exc


def validate_header(kind: str, header: Mapping[str, Any]) -> dict[str, Any]:
    """Prüft einen Header gegen das Modell und gibt ihn normalisiert zurück."""
    spec = KINDS.get(kind)
    if spec is None:
        raise ValueError(f"unbekannte Event-Art: {kind!r}")
    model = spec.model.model_validate(dict(header))
    data = model.model_dump(mode="json", exclude_none=True)
    _reject_floats(data, kind)
    return data


def _reject_floats(obj: Any, where: str) -> None:
    if isinstance(obj, float):
        raise ValueError(f"Floats sind in Headern nicht erlaubt ({where})")
    if isinstance(obj, Mapping):
        for v in obj.values():
            _reject_floats(v, where)
    elif isinstance(obj, list | tuple):
        for v in obj:
            _reject_floats(v, where)


def canonical_json(obj: Any) -> bytes:
    """Kanonisches JSON: sortierte Schlüssel, keine Leerzeichen, UTF-8, keine Floats."""
    _reject_floats(obj, "canonical_json")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
