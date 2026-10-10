"""Rahmenprotokoll v1 zwischen Shim und Daemon über ``term.sock``.

Architektur 3.7. Nur Standardbibliothek.

Rahmen: ``u32 Länge (big endian) | u8 Typ | Nutzlast``. Länge zählt nur die
Nutzlast und ist höchstens :data:`MAX_PAYLOAD`.

Shim an Daemon
    HELLO  JSON  {"proto": 1, "terminal_id", "tty", "shell", "term", "rows",
                  "cols", "tmux_pane", "window_id", "shim_version", "pid",
                  "display": {"DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY",
                              "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR"},
                  "resume_from_seq": int | null}
    OUT    binär ``>QQqq`` (seq, stream_off, t_wall_ns, t_mono_ns) + Bytes.
           Bytes sind der aufgezeichnete Strom: genau das, was angezeigt wurde,
           ohne entfernte Ariadne-Marker und ohne gefilterte Sequenzen.
    EVENT  JSON  {"seq": int, "kind": <Event-Art aus ariadne.events>, ...Felder}
           Erlaubte Arten: term.mark, term.resize, term.ctx_snapshot, term.gap,
           term.close, term.osc52_blocked, term.marker_forged. Ohne ``seq`` und
           ``kind`` entsprechen die Felder genau dem Modell in ``ariadne.events``
           (inklusive ``terminal_id``, das der Daemon zur Sicherheit überschreibt).
           ``term.gap``: ``stream_off`` ist der Beginn der Lücke, ``bytes_lost``
           ihre Länge; danach geht der Strom bei ``stream_off + bytes_lost`` weiter.
           Dazu die Hotkey-Anfragen (``req.*``), aus denen der Daemon Events
           bzw. Entscheide macht:
             "req.rec"      {"on": bool|null}  (null schaltet um)
             "req.ctx.set"  {"host"?, "user"?, "stage_kind"?}  oberste Stufe setzen
             "req.ctx.push" {"host"?, "user"?, "stage_kind"?}  neue Stufe
             "req.ctx.pop"  {}                                 oberste Stufe schliessen
             "req.keystep"  {"step": foothold|privesc|pivot|loot, "host"?, "note"?}
             "req.shot"     {"mode"?: window|monitor|region}
           Die Stufenart heisst ``stage_kind`` (``kind`` ist die Event-Art);
           ``ctx_kind`` wird ebenfalls angenommen. ``host`` ist der eingegebene
           Text (IP oder Name); der Daemon normalisiert zu ``ip:default/<ip>``
           bzw. ``name:<name>`` und löst nie auf. Optional schickt der Shim bei
           jedem ``req.*`` ``terminal_id`` und ``stream_off`` mit; der Daemon
           ignoriert beide und nimmt seine eigenen Werte. Der Shim setzt nie
           selbst eine Operator-ID.
    BYE    JSON  {"exit_code": int|null}

Daemon an Shim
    STATE  JSON  {"rec": "off"|"on"|"waiting"|"offline", "project": slug|null,
                  "project_id": str|null, "profile": "lab"|"customer"|null,
                  "bound_project_id": str|null, "stack": [Stage-Dicts],
                  "suggestion": str|null, "hosts": [str], "title_extra": str|null}
           ``offline`` sendet der Daemon nie; der Shim nutzt den Wert intern
           (Daemon nicht erreichbar) und behandelt einen empfangenen Wert wie
           «letzten bekannten Zustand beibehalten». ``title_extra`` ist eine
           kurze Rückmeldung (etwa 5 s), z. B. ``REC pausiert: <slug>``.
    ACK    JSON  {"seq": int}  bis einschliesslich dieser Sequenz gespeichert.

Sequenznummern: OUT und EVENT teilen sich eine fortlaufende ``seq`` pro
Terminal (ab 1). Nach einem Reconnect sendet der Shim alles ab
``resume_from_seq`` erneut; der Daemon verwirft Rahmen mit ``seq`` kleiner
oder gleich der höchsten empfangenen ``seq`` idempotent (und wiederholt nur
das letzte ACK).

ACK-Semantik: Der Daemon bestätigt erst, wenn ein Rahmen und alle davor
gespeichert (oder bewusst verworfen, etwa bei REC aus) sind. Im Zustand
``waiting`` (Projekt gesperrt) puffert er im RAM und bestätigt erst nach dem
Speichern. Wegen des Rückhalts des Redaktors kann ein ACK um höchstens die
Länge des längsten eigenen Secrets minus eins hinterherhinken, bis das nächste
EVENT oder der Leerlauf-Flush kommt. EVENTs müssen nach den vorangehenden
OUT-Bytes gesendet werden, damit Journal- und Strom-Reihenfolge stimmen.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Any

__all__ = [
    "PROTO_VERSION",
    "MAX_PAYLOAD",
    "HELLO", "OUT", "EVENT", "BYE", "STATE", "ACK",
    "Frame",
    "FrameDecoder",
    "ProtocolError",
    "encode_frame",
    "encode_json",
    "encode_out",
    "decode_out",
    "decode_json",
]

PROTO_VERSION = 1
MAX_PAYLOAD = 1 << 20  # 1 MiB

HELLO = 1
OUT = 2
EVENT = 3
BYE = 4
STATE = 10
ACK = 11

_TYPES = {HELLO, OUT, EVENT, BYE, STATE, ACK}
_HDR = struct.Struct(">IB")
_OUT = struct.Struct(">QQqq")


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
