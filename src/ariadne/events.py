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

**Zeit (E96).** Massgeblich ist die Zeit, die der Shim beim Lesen misst:
``t_shim_ns`` (Wanduhr, CLOCK_REALTIME) und ``mono_ns`` (CLOCK_MONOTONIC) im
Header. Die Spalte ``ts_utc_ns`` des Journals ist nur noch die Empfangszeit im
Daemon (Kontrollfeld). ``term.out`` und ``term.input`` tragen zusätzlich einen
Zeitindex ``tix``: Paare ``(rel_off, dt_us)``, ab dem Byte ``rel_off`` des Bodys
gilt die Zeit ``t_shim_ns + dt_us * 1000`` (bzw. ``mono_ns + dt_us * 1000``).
Das erste Byte hat implizit ``(0, 0)``. Siehe :func:`body_time`.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

__all__ = [
    "Layer",
    "KindSpec",
    "KINDS",
    "canonical_json",
    "validate_header",
    "layer_of",
    "Redaction",
    "Stage",
    "MAX_TIX",
    "body_time",
    "shim_time",
]

Layer = Literal["raw", "decision", "system"]
Mark = Literal["A", "B", "C", "D"]
GapReason = Literal[
    "rec_off", "buffer_overflow", "daemon_down", "project_switch",
    "sensitive_output", "locked", "disk_low", "shim_error",
    "multiplexer",  # tmux/screen-Client im Vordergrund: die Panes haben eigene Shims (A3.9)
    "pause",  # Pause des Nutzers (F12 r, ariadne pause), E22
    "no_project",  # kein Projekt aktiv und Vorlauf nicht übernommen (E95)
]
StageKind = Literal[
    "local", "su", "ssh", "winrm", "remote", "revshell", "msf", "meterpreter", "db", "unknown"
]
StageState = Literal["active", "suspended"]
StageSource = Literal["auto", "hotkey", "webui", "cli", "suggestion"]
Keystep = Literal["foothold", "privesc", "pivot", "loot"]
WorkStatus = Literal["open", "in_progress", "dead_end", "done", "out_of_scope"]
AccessLevel = Literal["none", "user", "admin"]
Origin = Literal["shim", "webui", "cli", "watcher", "gateway", "daemon", "import", "preroll"]
PauseSource = Literal["hotkey", "cli", "webui"]
ProjectEndReason = Literal["stop", "idle", "switch", "lock", "shutdown"]

MAX_TIX = 4096  # Einträge im Zeitindex eines term.out/term.input


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class _ShimTime(_M):
    """Zeit des Shims beim Lesen (E96). Fehlt bei alten Shims und bei Events des Daemons,
    deren Shim-Zeit er nicht kennt; dann gilt die Empfangszeit (Spalte ``ts_utc_ns``)."""

    t_shim_ns: int | None = None
    mono_ns: int | None = None


def _check_tix(tix: Sequence[Sequence[int]] | None, length: int) -> None:
    if not tix:
        return
    if len(tix) > MAX_TIX:
        raise ValueError("Zeitindex zu lang")
    prev_off, prev_dt = 0, 0
    for entry in tix:
        if len(entry) != 2:
            raise ValueError("Zeitindex: Paare (rel_off, dt_us) erwartet")
        rel, dt = entry
        if not prev_off < rel < length or dt < prev_dt:
            raise ValueError("Zeitindex: rel_off steigend innerhalb des Bodys, dt_us nicht fallend")
        prev_off, prev_dt = rel, dt


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
    host_source: StageSource | None = Field(
        default=None, description="Herkunft des Hosts; 'auto' = aus der Auswertung (erster Callback, E23). "
                                  "Solche Hosts stehen nie im Journal (ContextStack.journal_snapshot)")


# --------------------------------------------------------------------------- #
# Schicht 1: Rohereignisse
# --------------------------------------------------------------------------- #


class TermOpen(_ShimTime):
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
    """Output-Chunk. Die Bytes stehen im Body, nicht im Header.

    ``t_shim_ns``/``mono_ns`` gelten für das erste Byte, ``tix`` für spätere
    Lesevorgänge (siehe Moduldoku). ``time_suspect`` setzt der Daemon, wenn die
    Shim-Zeit unplausibel ist (Abweichung zur Empfangszeit über 5 s oder
    rückwärts laufende monotone Uhr). ``redactions`` bleibt seit E72 leer
    (der Daemon schwärzt nicht mehr vor dem Speichern); alte Journale haben Einträge.
    """

    terminal_id: str
    stream_off: int = Field(ge=0)
    length: int = Field(ge=0)
    t_shim_ns: int
    mono_ns: int | None = None
    redactions: tuple[Redaction, ...] = ()
    tix: tuple[tuple[int, int], ...] | None = None
    time_suspect: bool | None = None

    @model_validator(mode="after")
    def _tix_ok(self) -> TermOut:
        _check_tix(self.tix, self.length)
        return self


class TermInput(_M):
    """Eingabe ans Kind (E26): genau die Bytes, die der Shim an das Programm im PTY
    weitergibt, auch Passwörter ohne Echo. Nicht dabei: Hotkey-Folgen und Eingaben
    im Mini-Prompt, die Ariadne selbst verbraucht. Die Bytes stehen im Body.

    ``stream_off`` ist der Ausgabe-Offset beim ersten Byte, ``out_end`` der beim
    letzten (Bezug zum Output). ``paste``: der ganze Inhalt kam als Bracketed Paste.
    ``no_echo`` (E104, additiv): Der Shim sah beim Tippen den Passwortmodus des Kindes
    (``ECHO`` aus, ``ICANON`` an). Nur eine Markierung: gespeichert wird immer alles,
    angezeigt nur verdeckt (:mod:`ariadne.ingest.inputs`).
    Nie in Logs; an Terminal-Senken nur über ``term_safe``.
    """

    terminal_id: str
    stream_off: int = Field(ge=0)
    out_end: int = Field(ge=0)
    length: int = Field(ge=0)
    t_shim_ns: int
    mono_ns: int | None = None
    tix: tuple[tuple[int, int], ...] | None = None
    paste: bool | None = None
    time_suspect: bool | None = None
    no_echo: bool | None = None

    @model_validator(mode="after")
    def _ok(self) -> TermInput:
        if self.out_end < self.stream_off:
            raise ValueError("out_end vor stream_off")
        _check_tix(self.tix, self.length)
        return self


class TermPause(_M):
    """Pause des Nutzers beginnt (E22). Das Ende markiert das ``term.gap`` mit Grund
    ``pause``, das der Shim beim Fortsetzen schickt (auch mit ``bytes_lost=0``)."""

    terminal_id: str
    stream_off: int = Field(ge=0)
    until_ns: int = Field(ge=0, description="geplantes Ende, Wanduhr in ns")
    source: PauseSource


class TermPreroll(_M):
    """Vorlauf übernommen (E95): Davor geschriebene Events dieses Terminals mit
    ``origin='preroll'`` stammen aus dem RAM-Puffer, mit ihren Original-Zeiten."""

    terminal_id: str
    from_off: int = Field(ge=0)
    to_off: int = Field(ge=0)
    frames: int = Field(ge=0)
    t_first_ns: int | None = None
    t_last_ns: int | None = None
    dropped_bytes: int = Field(ge=0, default=0)


class TermMarkEv(_ShimTime):
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


class TermResize(_ShimTime):
    terminal_id: str
    stream_off: int = Field(ge=0)
    rows: int = Field(ge=0, le=1000)
    cols: int = Field(ge=0, le=1000)


class TermCtxSnapshot(_ShimTime):
    terminal_id: str
    stream_off: int = Field(ge=0)
    stack: tuple[Stage, ...]


class TermGap(_ShimTime):
    terminal_id: str
    stream_off: int = Field(ge=0)
    reason: GapReason
    bytes_lost: int = Field(ge=0, default=0)


class TermClose(_ShimTime):
    terminal_id: str
    stream_off: int = Field(ge=0)
    exit_code: int | None = None


class TermOsc52Blocked(_ShimTime):
    terminal_id: str
    stream_off: int = Field(ge=0)
    length: int = Field(ge=0)


class TermMarkerForged(_ShimTime):
    terminal_id: str
    stream_off: int = Field(ge=0)
    reason: Literal["bad_nonce", "replay", "not_foreground", "malformed", "oversize"]


class RecSet(_M):
    """Globaler REC-Schalter bis v0.1. Seit E22 (Daueraufnahme) schreibt der Daemon
    kein ``rec.set`` mehr; alte Journale enthalten es noch."""

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
    redactions: tuple[Redaction, ...] = Field(
        default=(), description="Eigene Secrets im Inhalt, vor dem Speichern längenerhaltend geschwärzt "
                                "(start/end: Byte-Offsets in der Datei)")


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
    # Bau v0.1-Screenshots (Teil «screenshots»): Kontext zum Zeitpunkt der Aufnahme
    dhash: str | None = Field(default=None, description="Differenz-Hash (16 Hex) für Beinahe-Duplikate")
    host: str | None = Field(default=None, description="Host der obersten Stufe des Terminals (nicht lokal)")
    host_auto: bool = Field(default=False, description="host aus der Auswertung (E23), nicht vom Nutzer")
    stack: tuple[Stage, ...] | None = Field(default=None, description="Kontextstapel ohne Auto-Hosts")


class NetRoute(_M):
    cmd_id: str
    target: str
    src_ip: str | None = None
    dev: str | None = None
    via: str | None = None


class NetLocalAddrs(_M):
    """Adressen der eigenen Interfaces von Kali (A5), gelesen aus ``/proc/net/fib_trie``
    und ``/proc/net/if_inet6`` (eigener Kernel, kein Befehl, kein Paket).

    Immer die vollständige aktuelle Menge, kanonisch (``ipaddress``), sortiert,
    ohne Duplikate; Loopback und Link-Local dürfen dabei sein. Der Daemon schreibt
    es beim Öffnen eines Projekts und wenn sich die Menge ändert. Die Auswertung
    behandelt jede Adresse, die je in einem solchen Event oder als ``net.route.src_ip``
    vorkam, als eigene Adresse.
    """

    addrs: tuple[str, ...] = Field(max_length=256)
    source: Literal["proc"] = "proc"


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


class SystemProjectEnd(_M):
    """Das Projekt endet (E22): ``stop``, Leerlauf (``idle``, mit Dauer), Wechsel zu einem
    anderen Projekt, ``lock`` oder Daemon-Ende. Steht vor dem Checkpoint ``close``."""

    reason: ProjectEndReason
    idle_s: int | None = Field(default=None, ge=0)


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
    """Kontext für einen Offset-Bereich setzen (auch rückwirkend).

    Wirkt auf die Stufe, die bei ``from_off`` oben liegt (bzw. die Stufe
    ``depth``), ab ``from_off`` bis ``to_off``; ``to_off=None`` heisst: bis
    diese Stufe endet. Liegt oben Kali, legt der Entscheid wie
    ``ContextStack.set_top`` eine neue Stufe an. Bei Überschneidungen gewinnt
    der spätere Entscheid (höhere ``seq``). ``host`` ist die eingegebene
    Kennung (``ip:default/<ip>``, ``name:<name>``). Die Projektion v0.1
    überträgt den Host vereinfachend auf die ganze Stufe, die ``from_off``
    enthält (eine Remote-Sitzung gehört zu genau einem Host).
    """

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
    """Denkanstoss erledigt (``d.suggestion.done``) oder verworfen (``d.suggestion.dismiss``).

    ``basis`` ist der Fingerabdruck des Anlasses zum Zeitpunkt des Entscheids (web-api.md 18.6):
    «erledigt» gilt nur, solange der Anlass gleich bleibt; «verworfen» gilt immer. Ergänzt im Bau
    v0.1-Oberfläche (additiv, ältere Einträge ohne ``basis`` bleiben gültig)."""

    suggestion_key: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=500)
    basis: str | None = Field(default=None, min_length=1, max_length=64)


class DLabNotCustomer(_M):
    """Bestätigung «Das ist kein Kundenauftrag» (Architektur 8.1)."""

    scope_version: int


class DUnitDistrust(_M):
    """Rückgängig pro Befehl (E42): Alle Claims, die nur aus der Evidenzgruppe dieses
    Befehls stammen (Einheiten mit dieser ``cmd_id`` und Dateien mit
    ``file.observed.produced_by_cmd`` = ``cmd_id``), werden verworfen; Claims mit
    weiteren Quellen verlieren diese Quellen. Übersteht Reparse, aufhebbar mit ``d.revoke``."""

    cmd_id: str = Field(min_length=3, max_length=200)
    reason: str | None = Field(default=None, max_length=500)


class DUnitPhase(_M):
    """Phase eines Befehls im Writeup (E62, Architektur 8.7): korrigiert den Vorschlag der Regeln
    (:mod:`ariadne.ingest.proj_phases`). Gilt je Vorlage; der jüngste nicht widerrufene Entscheid
    gewinnt. ``omit`` nimmt den Befehl aus dem Writeup. Übersteht Reparse, aufhebbar mit
    ``d.revoke``. Ergänzt im Bau v0.1-Export, nur additiv."""

    cmd_id: str = Field(min_length=3, max_length=200)
    template: Literal["cys", "htb"]
    phase: Literal[
        "recon", "scanning", "exploitation", "post", "reporting",
        "enumeration", "foothold", "privesc", "pivot", "loot", "lessons", "omit",
    ]
    reason: str | None = Field(default=None, max_length=500)


class DAiAllowCloud(_M):
    """Ausdrückliche Freigabe der Cloud-KI für dieses Projekt (``ariadne ai allow-cloud``, E65, A 6.2).
    Nur im Terminal; aufhebbar mit ``d.revoke``. Ergänzt im Bau v0.1-KI, nur additiv."""

    functions: list[Literal["denkanstoss"]] = Field(default_factory=lambda: ["denkanstoss"], max_length=4)


class DAiTemplateRef(_M):
    template_id: str = Field(min_length=1, max_length=64)
    host_id: str | None = Field(default=None, max_length=300)
    service_id: str | None = Field(default=None, max_length=300)


class DAiItem(_M):
    """Ein geprüfter KI-Denkanstoss (Modelltext, nur als Text anzuzeigen)."""

    kind: Literal["hypothesis", "question", "goal"]
    title: str = Field(min_length=1, max_length=200)
    reason: str = Field(max_length=600)
    confirmed_if: str = Field(min_length=1, max_length=400)
    refuted_if: str = Field(min_length=1, max_length=400)
    question: str = Field(max_length=400)
    direction: str = Field(max_length=500)
    goal_id: str | None = Field(default=None, max_length=64)
    evidence: list[str] = Field(default_factory=list, max_length=8)
    host_id: str | None = Field(default=None, max_length=300)
    service_id: str | None = Field(default=None, max_length=300)
    claim_keys: list[str] = Field(default_factory=list, max_length=5)
    templates: list[DAiTemplateRef] = Field(default_factory=list, max_length=3)
    flags: list[Literal["injection_suspect"]] = Field(default_factory=list, max_length=1)


class DAiDenkanstoss(_M):
    """Ergebnis eines KI-Auftrags «Denkanstoss» (Architektur 6.3): höchstens vier geprüfte Einträge. Der
    Zustand jedes Eintrags folgt wie bei Regeln aus ``d.suggestion.*``; ``d.revoke`` blendet alle aus.
    Ergänzt im Bau v0.1-KI, nur additiv."""

    job_id: str = Field(min_length=1, max_length=64)
    call_id: str = Field(min_length=1, max_length=64)
    provider: Literal["cloud", "local"]
    model: str = Field(min_length=1, max_length=100)
    prompt_version: str = Field(min_length=1, max_length=64)
    items: list[DAiItem] = Field(default_factory=list, max_length=4)
    dropped: int = Field(default=0, ge=0, le=1000)
    injection_suspect: int = Field(default=0, ge=0, le=1000)


# Findings (E113, web-api.md 18.5). Ergänzt im Bau v0.1-Oberfläche, nur additiv.
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["draft", "final"]
# Nur ASCII-Ziffern und ganzer Text (fullmatch): ``$`` passte vor einem LF am Ende, ``\d`` auf
# Ziffern aller Schriften (Korrektur SEC-FIND-1).
ATTACK_ID_RE = re.compile(r"T[0-9]{4}(\.[0-9]{3})?")
CVE_ID_RE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
_ATTACK_RE = ATTACK_ID_RE
_CVE_RE = CVE_ID_RE


def title_ok(text: str) -> bool:
    """Titel eines Findings: keine Zeilentrenner (LF, CR, NEL, U+2028, U+2029) und keine Steuer-,
    Format-, Surrogat-, privaten oder nicht zugewiesenen Zeichen (Kategorie C*, Zl, Zp)."""
    return not any(unicodedata.category(ch)[0] == "C" or unicodedata.category(ch) in ("Zl", "Zp")
                   for ch in text)


class DFindingRef(_M):
    """ATT&CK-Technik oder CVE als Text; ``supported``: vom Menschen als belegt markiert."""

    id: str = Field(min_length=1, max_length=32)
    supported: StrictBool = False


class DEvidenceRef(_M):
    """Beleg eines Findings: Claim und/oder Einheit mit Zeilenbereich (inklusiv, 0-basiert)."""

    claim_key: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    unit_id: str | None = Field(default=None, min_length=1, max_length=300)
    lines: tuple[int, int] | None = None

    @model_validator(mode="after")
    def _check(self) -> DEvidenceRef:
        if self.claim_key is None and self.unit_id is None:
            raise ValueError("claim_key oder unit_id nötig")
        if self.lines is not None and not (0 <= self.lines[0] <= self.lines[1]):
            raise ValueError("lines: 0 <= start <= ende")
        return self


def _check_refs(refs: Sequence[DFindingRef], rx: re.Pattern[str], what: str) -> None:
    for r in refs:
        if not rx.fullmatch(r.id):
            raise ValueError(f"{what}: ungültige Kennung")


class _FindingFields(_M):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    severity: Severity | None = None
    status: FindingStatus | None = None
    affected: tuple[str, ...] | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=20_000)
    remediation: str | None = Field(default=None, max_length=20_000)
    attack: tuple[DFindingRef, ...] | None = Field(default=None, max_length=20)
    cves: tuple[DFindingRef, ...] | None = Field(default=None, max_length=20)

    @model_validator(mode="after")
    def _check_fields(self) -> _FindingFields:
        if self.title is not None and not title_ok(self.title):
            raise ValueError("title ohne Zeilenumbruch und ohne Steuerzeichen")
        for a in self.affected or ():
            if not a or len(a) > 600:
                raise ValueError("affected: ungültige Kennung")
        _check_refs(self.attack or (), _ATTACK_RE, "attack")
        _check_refs(self.cves or (), _CVE_RE, "cves")
        return self


class DFindingCreate(_FindingFields):
    """Neues Finding; ``finding_id`` ist die ``decision_id`` dieses Entscheids."""

    title: str = Field(min_length=1, max_length=200)  # type: ignore[assignment]
    evidence: tuple[DEvidenceRef, ...] = Field(default=(), max_length=100)
    created_from: DEvidenceRef | None = None


class DFindingUpdate(_FindingFields):
    """Genannte Felder ersetzen, nicht genannte bleiben."""

    finding_id: str = Field(min_length=1, max_length=64)


class DFindingEvidenceAdd(DEvidenceRef):
    finding_id: str = Field(min_length=1, max_length=64)


class DFindingEvidenceRemove(_M):
    finding_id: str = Field(min_length=1, max_length=64)
    evidence_id: str = Field(min_length=1, max_length=64)


class DFindingDelete(_M):
    finding_id: str = Field(min_length=1, max_length=64)
    reason: str | None = Field(default=None, max_length=500)


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
        _k("term.input", "raw", TermInput, has_body=True),
        _k("term.pause", "raw", TermPause),
        _k("term.preroll", "raw", TermPreroll),
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
        _k("net.local_addrs", "raw", NetLocalAddrs),
        _k("clock.check", "raw", ClockCheck),
        _k("ai.call", "raw", AiCall),
        # System
        _k("system.project_created", "system", ProjectCreated),
        _k("system.checkpoint", "system", SystemCheckpoint),
        _k("system.redaction", "system", SystemRedaction, has_body=True),
        _k("system.clock_jump", "system", SystemClockJump),
        _k("system.migration", "system", SystemMigration),
        _k("system.project_end", "system", SystemProjectEnd),
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
        _k("d.unit.distrust", "decision", DUnitDistrust),
        _k("d.ai.allow_cloud", "decision", DAiAllowCloud),
        _k("d.ai.denkanstoss", "decision", DAiDenkanstoss),
        _k("d.unit.phase", "decision", DUnitPhase),
        _k("d.finding", "decision", DGeneric),
        _k("d.finding.create", "decision", DFindingCreate),
        _k("d.finding.update", "decision", DFindingUpdate),
        _k("d.finding.evidence.add", "decision", DFindingEvidenceAdd),
        _k("d.finding.evidence.remove", "decision", DFindingEvidenceRemove),
        _k("d.finding.delete", "decision", DFindingDelete),
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


# --------------------------------------------------------------------------- #
# Zeit (E96)
# --------------------------------------------------------------------------- #


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def shim_time(header: Mapping[str, Any], fallback_ns: int) -> int:
    """Wanduhr eines Events: ``t_shim_ns`` aus dem Header, sonst ``fallback_ns``
    (die Empfangszeit ``ts_utc_ns`` des Journals)."""
    t = _int(header.get("t_shim_ns"))
    return t if t is not None else fallback_ns


def body_time(header: Mapping[str, Any], rel: int) -> tuple[int | None, int | None]:
    """Shim-Zeit (Wanduhr, monotone Uhr) des Bytes ``rel`` im Body von ``term.out``
    oder ``term.input`` (``rel = offset - stream_off`` bei ``term.out``).

    Ohne ``t_shim_ns`` ergibt sich ``(None, None)``. ``mono_ns`` ist ``None``, wenn
    der Header keine monotone Zeit hat.
    """
    wall = _int(header.get("t_shim_ns"))
    mono = _int(header.get("mono_ns"))
    if wall is None:
        return None, None
    dt = 0
    for entry in header.get("tix") or ():
        r, d = entry[0], entry[1]
        if r > rel:
            break
        dt = d
    add = dt * 1000
    return wall + add, (mono + add if mono is not None else None)
