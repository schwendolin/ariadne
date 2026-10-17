"""Rahmenprotokoll zwischen Shim und Daemon über ``term.sock`` (Version 2).

Architektur 3.7, Vertrag v0.1-Bedienung. Nur Standardbibliothek.

Rahmen: ``u32 Länge (big endian) | u8 Typ | Nutzlast``. Länge zählt nur die
Nutzlast und ist höchstens :data:`MAX_PAYLOAD`.

Versionen: Der Shim sendet ``proto`` 2. Der Daemon nimmt 1 und 2 an
(:data:`ACCEPTED_PROTOS`): Ein Shim aus der Zeit vor einem Update läuft weiter.
v1 kennt nur ``OUT`` ohne Zeitindex, keine Eingaben und die alten ``rec``-Werte.

Shim an Daemon
    HELLO  JSON  {"proto": 2, "terminal_id", "tty", "shell", "term", "rows",
                  "cols", "tmux_pane", "window_id", "shim_version", "pid",
                  "display": {"DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
                              "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"},
                  "resume_from_seq": int | null,
                  "stack": [Stage-Dicts] (Stapel des Shims),
                  "bound_project_id": str | null, "bound_slug": str | null,
                  "gap_hint": "buffer_overflow" | null,
                  "pause_until_ns": int | null,   (v2) laufende Pause, Wanduhr
                  "mux": bool}                    (v2) Multiplexer-Client im Vordergrund
           Stapel, Bindung und Pause übernimmt der Daemon nur für ein Terminal,
           das er noch nicht kennt (erster Kontakt, Daemon-Neustart). ``gap_hint``:
           Der Ring hat Rahmen verdrängt; der Daemon sieht den Sprung im Offset vor
           dem ``term.gap`` des Shims und vermerkt ihn mit diesem Grund.
    OUT    (v1) binär ``>QQqq`` (seq, stream_off, t_wall_ns, t_mono_ns) + Bytes.
    OUTX   (v2) binär ``>QQqqH`` (seq, stream_off, t_wall_ns, t_mono_ns, n) +
           n Mal ``>II`` (rel_off, dt_us) + Bytes. Zeitindex: ab Byte ``rel_off``
           gilt ``t + dt_us * 1000`` (Wanduhr und monotone Uhr); das erste Byte hat
           implizit (0, 0). ``rel_off`` steigt streng und liegt im Body, ``dt_us``
           fällt nie, ``n`` höchstens :data:`MAX_TIX`. Der Shim legt einen neuen
           Eintrag nur an, wenn seit dem letzten mindestens 1 ms vergangen ist.
           Bytes sind der aufgezeichnete Strom: genau das, was angezeigt wurde,
           ohne entfernte Ariadne-Marker und ohne gefilterte Sequenzen.
    INPUT  (v2) binär ``>QQQqqHB`` (seq, stream_off, out_end, t_wall_ns, t_mono_ns,
           n, flags) + n Mal ``>II`` (rel_off, dt_us) + Bytes. Die Bytes sind genau
           das, was der Shim ans Kind schreibt (E26), ohne Hotkey-Folgen und ohne
           Eingaben im Mini-Prompt. ``stream_off``/``out_end``: Ausgabe-Offset beim
           ersten bzw. letzten Byte. ``flags`` Bit 0: Bracketed Paste (ein Paste ist
           genau ein INPUT). ``flags`` Bit 1 (E104, additiv): Beim Tippen stand das
           Kind im Modus ``ECHO`` aus und ``ICANON`` an (``getpass`` von sudo, ssh, su,
           mysql); gesetzt, sobald ein Byte des Bündels so getippt wurde. Ältere
           Daemons ignorieren das Bit. Der Shim bündelt bis Enter (CR, LF), Ctrl-C, Ctrl-D,
           Paste-Grenze, 4 KiB oder 1 s nach dem ersten Byte.
    EVENT  JSON  {"seq": int, "kind": <Event-Art aus ariadne.events>, ...Felder}
           Erlaubte Arten: term.mark, term.resize, term.ctx_snapshot, term.gap,
           term.close, term.osc52_blocked, term.marker_forged. Ohne ``seq`` und
           ``kind`` entsprechen die Felder genau dem Modell in ``ariadne.events``
           (inklusive ``terminal_id``, das der Daemon zur Sicherheit überschreibt).
           v2: jedes dieser Events trägt ``t_shim_ns`` und ``mono_ns`` des
           Lesevorgangs, in dem es entstand. Stapel in ``term.ctx_snapshot`` ohne
           automatisch gesetzte Hosts (``ContextStack.journal_snapshot``).
           ``term.gap``: ``stream_off`` ist der Beginn der Lücke, ``bytes_lost``
           ihre Länge; danach geht der Strom bei ``stream_off + bytes_lost`` weiter.
           Grund ``pause`` schickt der Shim beim Fortsetzen immer, auch mit 0 Bytes.
           Dazu die Anfragen (``req.*``), aus denen der Daemon Events, Entscheide
           oder Zustand macht:
             "req.pause"    (v2) {"minutes": int|null}  null: umschalten (F12 r,
                            Standard 10 min); 0: fortsetzen; >0: pausieren
             "req.rebind"   (v2) {"stream_off": int}  Zustand ``held``: gültiger
                            A-Marker (fg_shell) und Stapel nur lokal gesehen bzw.
                            beim Eintritt schon am Prompt
             "req.status"   (v2) {"mux": bool}  Multiplexer im Vordergrund (Anzeige)
             "req.rec"      (v1) {"on": bool|null}; v2-Daemon: wie req.pause null
             "req.ctx.set"  {"host"?, "user"?, "stage_kind"?}  oberste Stufe setzen
             "req.ctx.push" {"host"?, "user"?, "stage_kind"?}  neue Stufe
             "req.ctx.pop"  {}                                 oberste Stufe schliessen
             "req.keystep"  {"step": foothold|privesc|pivot|loot, "host"?, "note"?}
             "req.shot"     {"mode"?: window|monitor|region}
             "req.ctx.sync" {"stack": [Stage-Dicts]}  Stapel des Shims, solange
                            er nicht aufnimmt (der Daemon sieht dann keine Marker)
           Die Stufenart heisst ``stage_kind`` (``kind`` ist die Event-Art);
           ``ctx_kind`` wird ebenfalls angenommen. ``host`` ist der eingegebene
           Text (IP oder Name); der Daemon normalisiert zu ``ip:default/<ip>``
           bzw. ``name:<name>`` und löst nie auf. Optional schickt der Shim bei
           jedem ``req.*`` ``terminal_id`` und ``stream_off`` mit; der Daemon
           nimmt seine eigenen Werte, nur bei fehlender Aufnahme ``stream_off``
           als Beginn einer neuen Stufe. Der Shim setzt nie selbst eine Operator-ID.
    BYE    JSON  {"exit_code": int|null}

Daemon an Shim
    STATE  JSON  {"rec": siehe unten, "project": slug|null,
                  "project_id": str|null, "profile": "lab"|"customer"|null,
                  "bound_project_id": str|null, "bound_slug": str|null,
                  "stack": [Stage-Dicts], "ctx_version": int, "daemon_id": str,
                  "pause_until_ns": int|null, "preroll_minutes": int,
                  "suggestion": str|null, "hosts": [str], "title_extra": str|null}
           ``rec`` (v2, :data:`REC_STATES`):
             "on"       Projekt aktiv, Aufnahme (Shim sendet)
             "paused"   Pause des Nutzers bis ``pause_until_ns`` (Shim sendet nichts)
             "preroll"  kein Projekt; der Daemon hält den Vorlauf im RAM (Shim sendet)
             "locked"   Projekt aktiv, aber Tresor gesperrt (Neustart, ``ariadne lock``);
                        Vorlauf wie ``preroll`` (Shim sendet)
             "held"     an ``bound_slug`` gebunden, Remote-Sitzung läuft, das Projekt ist
                        nicht offen: wird nicht gespeichert (Shim sendet nichts)
             "off"      nichts (Vorlauf abgeschaltet und kein Projekt)
             "waiting"  nur v1; "offline" sendet der Daemon nie (Shim-intern)
           Für Verbindungen mit proto 1 bildet der Daemon ab: on -> on,
           preroll/locked -> waiting, sonst -> off.
           ``stack`` übernimmt der Shim nur, wenn sich ``ctx_version`` seit dem
           letzten STATE dieser Verbindung geändert hat (Kontext-Entscheid oder
           automatischer Kontext aus der Auswertung, ``host_source`` = "auto").
           ``daemon_id`` ist pro Daemon-Start neu; wechselt sie, war der Daemon weg.
           ``offline`` sendet der Daemon nie; der Shim nutzt den Wert intern
           (Daemon nicht erreichbar) und behandelt einen empfangenen Wert wie
           «letzten bekannten Zustand beibehalten». ``title_extra`` ist eine
           kurze Rückmeldung (etwa 5 s).
    ACK    JSON  {"seq": int}  bis einschliesslich dieser Sequenz gespeichert.

Sequenznummern: OUT, OUTX, INPUT und EVENT teilen sich eine fortlaufende ``seq``
pro Terminal (ab 1). Nach einem Reconnect sendet der Shim alles ab
``resume_from_seq`` erneut; der Daemon verwirft Rahmen mit ``seq`` kleiner
oder gleich der höchsten empfangenen ``seq`` idempotent (und wiederholt nur
das letzte ACK).

ACK-Semantik: Der Daemon bestätigt erst, wenn ein Rahmen und alle davor
gespeichert, bewusst im Vorlauf gehalten oder bewusst verworfen sind.
EVENTs und INPUTs müssen nach den vorangehenden OUT-Bytes gesendet werden
(der Shim leert vorher seinen OUT-Puffer), damit Journal- und Strom-Reihenfolge
stimmen.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any

__all__ = [
    "PROTO_VERSION",
    "MAX_PAYLOAD",
    "ACCEPTED_PROTOS",
    "MAX_TIX",
    "REC_STATES",
    "CAPTURE_STATES",
    "INPUT_PASTE",
    "INPUT_NOECHO",
    "HELLO", "OUT", "EVENT", "BYE", "OUTX", "INPUT", "STATE", "ACK",
    "Frame",
    "OutFrame",
    "InputFrame",
    "FrameDecoder",
    "ProtocolError",
    "encode_frame",
    "encode_json",
    "encode_out",
    "decode_out",
    "encode_outx",
    "decode_outx",
    "encode_input",
    "decode_input",
    "decode_json",
    "frame_seq",
]

PROTO_VERSION = 2
ACCEPTED_PROTOS = (1, 2)
MAX_PAYLOAD = 1 << 20  # 1 MiB
MAX_TIX = 1024

HELLO = 1
OUT = 2
EVENT = 3
BYE = 4
OUTX = 5
INPUT = 6
STATE = 10
ACK = 11

REC_STATES = ("on", "paused", "preroll", "locked", "held", "off", "waiting", "offline")
CAPTURE_STATES = ("on", "preroll", "locked", "waiting")  # in diesen Zuständen sendet der Shim
INPUT_PASTE = 0x01
INPUT_NOECHO = 0x02  # E104: getippt mit ECHO aus und ICANON an (Passwortabfrage)

_TYPES = {HELLO, OUT, EVENT, BYE, OUTX, INPUT, STATE, ACK}
_HDR = struct.Struct(">IB")
_OUT = struct.Struct(">QQqq")
_OUTX = struct.Struct(">QQqqH")
_INPUT = struct.Struct(">QQQqqHB")
_TIX = struct.Struct(">II")


class ProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class Frame:
    type: int
    payload: bytes


def encode_frame(ftype: int, payload: bytes) -> bytes:
    if ftype not in _TYPES:
        raise ProtocolError(f"unbekannter Rahmentyp {ftype}")
    if len(payload) > MAX_PAYLOAD:
        raise ProtocolError("Nutzlast zu gross")
    return _HDR.pack(len(payload), ftype) + payload


def encode_json(ftype: int, obj: dict[str, Any]) -> bytes:
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
    return encode_frame(ftype, data)


def decode_json(payload: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(payload.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("ungültiges JSON") from exc
    if not isinstance(obj, dict):
        raise ProtocolError("JSON-Objekt erwartet")
    return obj


def encode_out(seq: int, stream_off: int, t_wall_ns: int, t_mono_ns: int, data: bytes) -> bytes:
    """OUT-Rahmen. ``data`` darf höchstens MAX_PAYLOAD - 32 Bytes lang sein."""
    return encode_frame(OUT, _OUT.pack(seq, stream_off, t_wall_ns, t_mono_ns) + data)


def decode_out(payload: bytes) -> tuple[int, int, int, int, bytes]:
    if len(payload) < _OUT.size:
        raise ProtocolError("OUT zu kurz")
    seq, off, wall, mono = _OUT.unpack_from(payload)
    return seq, off, wall, mono, payload[_OUT.size :]


@dataclass(frozen=True)
class OutFrame:
    seq: int
    stream_off: int
    t_wall_ns: int
    t_mono_ns: int
    tix: tuple[tuple[int, int], ...]
    data: bytes


@dataclass(frozen=True)
class InputFrame:
    seq: int
    stream_off: int
    out_end: int
    t_wall_ns: int
    t_mono_ns: int
    tix: tuple[tuple[int, int], ...]
    paste: bool
    data: bytes
    no_echo: bool = False  # E104: Flag-Bit 1


def _pack_tix(tix: tuple[tuple[int, int], ...] | list[tuple[int, int]], length: int) -> bytes:
    if len(tix) > MAX_TIX:
        raise ProtocolError("Zeitindex zu lang")
    out = bytearray()
    prev_off, prev_dt = 0, 0
    for rel, dt in tix:
        if not prev_off < rel < length or dt < prev_dt or dt > 0xFFFFFFFF:
            raise ProtocolError("Zeitindex ungültig")
        out += _TIX.pack(rel, dt)
        prev_off, prev_dt = rel, dt
    return bytes(out)


def _unpack_tix(payload: bytes, pos: int, n: int) -> tuple[tuple[tuple[int, int], ...], int]:
    if n > MAX_TIX:
        raise ProtocolError("Zeitindex zu lang")
    end = pos + n * _TIX.size
    if len(payload) < end:
        raise ProtocolError("Zeitindex abgeschnitten")
    tix = tuple(_TIX.unpack_from(payload, pos + i * _TIX.size) for i in range(n))
    length = len(payload) - end
    prev_off, prev_dt = 0, 0
    for rel, dt in tix:
        if not prev_off < rel < length or dt < prev_dt:
            raise ProtocolError("Zeitindex ungültig")
        prev_off, prev_dt = rel, dt
    return tix, end


def encode_outx(seq: int, stream_off: int, t_wall_ns: int, t_mono_ns: int, data: bytes,
                tix: tuple[tuple[int, int], ...] | list[tuple[int, int]] = ()) -> bytes:
    """OUTX-Rahmen (v2) mit Zeitindex. Wirft :class:`ProtocolError` bei ungültigem Index."""
    head = _OUTX.pack(seq, stream_off, t_wall_ns, t_mono_ns, len(tix))
    return encode_frame(OUTX, head + _pack_tix(tix, len(data)) + data)


def decode_outx(payload: bytes) -> OutFrame:
    if len(payload) < _OUTX.size:
        raise ProtocolError("OUTX zu kurz")
    seq, off, wall, mono, n = _OUTX.unpack_from(payload)
    tix, pos = _unpack_tix(payload, _OUTX.size, n)
    return OutFrame(seq, off, wall, mono, tix, payload[pos:])


def encode_input(seq: int, stream_off: int, out_end: int, t_wall_ns: int, t_mono_ns: int, data: bytes,
                 tix: tuple[tuple[int, int], ...] | list[tuple[int, int]] = (), *,
                 paste: bool = False, no_echo: bool = False) -> bytes:
    """INPUT-Rahmen (v2): Eingabe ans Kind. ``no_echo``: Passwortmodus des Kindes (E104)."""
    if out_end < stream_off:
        raise ProtocolError("out_end vor stream_off")
    flags = (INPUT_PASTE if paste else 0) | (INPUT_NOECHO if no_echo else 0)
    head = _INPUT.pack(seq, stream_off, out_end, t_wall_ns, t_mono_ns, len(tix), flags)
    return encode_frame(INPUT, head + _pack_tix(tix, len(data)) + data)


def decode_input(payload: bytes) -> InputFrame:
    if len(payload) < _INPUT.size:
        raise ProtocolError("INPUT zu kurz")
    seq, off, out_end, wall, mono, n, flags = _INPUT.unpack_from(payload)
    if out_end < off:
        raise ProtocolError("INPUT: out_end vor stream_off")
    tix, pos = _unpack_tix(payload, _INPUT.size, n)
    return InputFrame(seq, off, out_end, wall, mono, tix, bool(flags & INPUT_PASTE), payload[pos:],
                      no_echo=bool(flags & INPUT_NOECHO))


def frame_seq(ftype: int, payload: bytes) -> int:
    """``seq`` eines OUT-, OUTX- oder INPUT-Rahmens (ohne den Rest zu prüfen)."""
    if ftype in (OUT, OUTX, INPUT):
        if len(payload) < 8:
            raise ProtocolError("Rahmen zu kurz")
        return int.from_bytes(payload[:8], "big")
    raise ProtocolError("kein Datenrahmen")


class FrameDecoder:
    """Inkrementeller Decoder: ``feed(bytes)`` liefert vollständige Rahmen."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        self._buf += data
        frames: list[Frame] = []
        while len(self._buf) >= _HDR.size:
            length, ftype = _HDR.unpack_from(self._buf)
            if length > MAX_PAYLOAD:
                raise ProtocolError("Rahmen zu gross")
            if ftype not in _TYPES:
                raise ProtocolError(f"unbekannter Rahmentyp {ftype}")
            end = _HDR.size + length
            if len(self._buf) < end:
                break
            frames.append(Frame(ftype, bytes(self._buf[_HDR.size : end])))
            del self._buf[:end]
        return frames
