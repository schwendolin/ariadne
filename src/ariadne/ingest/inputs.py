"""Eingaben ohne Echo erkennen und verdecken (E104, E26, E99).

Ariadne speichert jede Eingabe vollständig (``term.input``, E26). Angezeigt werden
Eingaben ohne Echo aber nur verdeckt (``••••••••``); aufgedeckt wird nur ausdrücklich
und einzeln. Zwei Quellen sagen, ob eine Eingabe ein Echo hatte:

1. **Terminalmodus (lokal).** Der Shim prüft beim Aufzeichnen den Modus des Kindes
   (``tcgetattr`` auf dem Master). ``ECHO`` aus und ``ICANON`` an ist das Muster von
   ``getpass`` (sudo, ssh, su, mysql); dann trägt ``term.input`` ``no_echo = true``.
   Zeileneditoren (ZLE, readline) schalten ``ECHO`` und ``ICANON`` beide aus und echoen
   selbst; das ist kein Passwort.
2. **Echo-Vergleich (Remote-Shells, lokal im Raw-Modus).** :func:`echo_seen` prüft, ob
   die getippten druckbaren Zeichen in der Ausgabe ab dem ersten getippten Byte bis kurz
   nach dem Enter wieder erscheinen (:func:`output_window`). Fehlen sie, gilt die Eingabe
   als ohne Echo.

Grundsatz: lieber zu viel als zu wenig verdecken. Verdeckt wird auch, wenn die Ausgabe
fehlt (Lücke, Pause, noch nicht gespeichert) oder das Echo nicht eindeutig ist. Ein
kurzes Wort (unter :data:`ANYWHERE_MIN` Zeichen) zählt nur, wenn es eine angezeigte
Zeile beendet oder direkt vor dem Cursor steht, als die Zeile endete (Enter); sonst
könnte ein vorab getipptes Passwort zufällig im Prompt stehen. Der Cursor zählt, weil
Zeileneditoren rechts davon noch etwas zeigen können (rechter Prompt ``RPROMPT``,
Vorschläge von zsh-autosuggestions). Eine Tab-Vervollständigung ist ein Platzhalter: Was
die Shell ergänzt, kennt nur die Ausgabe.

Alle Funktionen sind rein, bis auf :func:`collect_inputs` und :func:`input_by_seq`,
die aus einem Journal lesen (``iter_events`` und, falls vorhanden, ``stream_slice``).
Die Texte sind Zieldaten bzw. Secrets: Die Senke kodiert sie (CLI ``term_safe``,
API JSON-String), und eigene Secrets ersetzt der Ausgang (``Redactor.redact_json``).
Nie in Logs.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

from ariadne.termsafe import visible

__all__ = [
    "MASK",
    "ANYWHERE_MIN",
    "TAIL_MAX",
    "TEXT_MAX",
    "HideReason",
    "InputVerdict",
    "typed_lines",
    "render_output",
    "echo_seen",
    "output_window",
    "classify",
    "display_text",
    "input_view",
    "collect_inputs",
    "input_by_seq",
]

MASK = "••••••••"
ANYWHERE_MIN = 12  # ab dieser Länge zählt ein Echo auch mitten in einer Zeile
TAIL_MAX = 8192  # so viel Ausgabe nach dem Enter gehört höchstens zum Echo
TEXT_MAX = 2000  # Länge des angezeigten Texts einer Eingabe
SLICE_LOOKBACK = 1 << 20  # term.out-Rahmen sind höchstens so lang (Protokoll MAX_PAYLOAD)

HideReason = Literal["tty_no_echo", "no_echo_seen", "no_output"]

_CSI = re.compile(rb"\x1b\[([0-9;?<=>!]*)([ -/]*)([@-~])")
_PASTE = (b"\x1b[200~", b"\x1b[201~")
_TAB = "\t"  # Platzhalter für eine Tab-Vervollständigung (was die Shell ergänzt, ist unbekannt)
_MAX_TABS = 4  # mehr Platzhalter in einer Zeile: kein Vergleich (dann verdeckt)
_MATCH_MAX = 4096  # so viel (vom Ende her) einer angezeigten Zeile prüft der Vergleich


@dataclass(frozen=True)
class InputVerdict:
    """Ergebnis für eine Eingabe. ``hidden``: nur verdeckt anzeigen. ``reason``: warum
    (``tty_no_echo`` Terminalmodus, ``no_echo_seen`` kein Echo in der Ausgabe,
    ``no_output`` Ausgabe fehlt). ``printable``: Zahl der druckbaren getippten Zeichen."""

    hidden: bool
    reason: HideReason | None
    printable: int


# --------------------------------------------------------------------------- getippt


def typed_lines(data: bytes) -> list[str]:
    """Was die Eingabe wirksam tippt, als Zeilen ohne leere Zeilen.

    Escape-Folgen (Pfeile, Paste-Klammern) fallen weg, Backspace und DEL löschen das
    letzte Zeichen, Ctrl-U die Zeile, Ctrl-W das letzte Wort. CR und LF trennen Zeilen,
    andere Steuerzeichen (Tab, Ctrl-C) fallen weg.
    """
    return [ln.replace(_TAB, "") for ln in _typed_tokens(data)]


def _typed_tokens(data: bytes) -> list[str]:
    """Wie :func:`typed_lines`, aber ein Tab bleibt als Platzhalter :data:`_TAB` stehen.

    Backspace direkt nach einem Tab löscht ein unbekanntes, vervollständigtes Zeichen: Der
    Platzhalter bleibt. Ctrl-W löscht ein Wort samt Platzhaltern darin.
    """
    for marker in _PASTE:
        data = data.replace(marker, b"")
    text = _strip_escapes(data).decode("utf-8", errors="replace")
    lines: list[str] = []
    cur: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch in "\r\n":
            if cur:
                lines.append("".join(cur))
            cur = []
        elif ch == _TAB:
            if not cur or cur[-1] != _TAB:
                cur.append(_TAB)
        elif cp in (0x08, 0x7F):
            if cur and cur[-1] != _TAB:
                cur.pop()
        elif cp == 0x15:  # Ctrl-U
            cur = []
        elif cp == 0x17:  # Ctrl-W
            while cur and cur[-1] == " ":
                cur.pop()
            while cur and cur[-1] != " ":
                cur.pop()
        elif cp < 0x20 or 0x80 <= cp <= 0x9F:
            continue
        else:
            cur.append(ch)
    if cur:
        lines.append("".join(cur))
    return [ln for ln in lines if ln.replace(_TAB, "").strip()]


def _strip_escapes(data: bytes) -> bytes:
    """Entfernt CSI-, SS3- und OSC-Folgen sowie einzelne ESC-Zeichen."""
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != 0x1B:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        nxt = data[i + 1]
        if nxt == 0x5B:  # CSI
            m = _CSI.match(data, i)
            i = m.end() if m else i + 2
        elif nxt == 0x5D:  # OSC bis BEL oder ST
            j = i + 2
            while j < n and data[j] != 0x07 and not (data[j] == 0x1B and j + 1 < n and data[j + 1] == 0x5C):
                j += 1
            i = j + (1 if j < n and data[j] == 0x07 else 2)
        elif nxt == 0x4F and i + 2 < n:  # SS3 (Pfeile im Anwendungsmodus)
            i += 3
        else:
            i += 2
    return bytes(out)


# --------------------------------------------------------------------------- Ausgabe


def render_output(data: bytes) -> list[str]:
    """Kleines Zeilenmodell der Ausgabe: CR, LF, Backspace und die häufigen CSI-Folgen für
    Cursor und Löschen (C, D, G, K, P, @). Andere Folgen fallen weg. Genug für das Echo
    von Shells und Zeileneditoren; ein Bildschirm-Programm (vim) bleibt unverstanden."""
    return [text.rstrip() for text, _ in _render(data)]


def _render(data: bytes) -> list[tuple[str, int]]:
    """Zeilen wie :func:`render_output` (ohne ``rstrip``), dazu je Zeile die Spalte des Cursors,
    als sie endete: beim LF bzw. beim ersten CR direkt davor (Shells beenden die Zeile nach
    Enter mit ``\\r\\r\\n``; der Cursor stand dann hinter dem Getippten)."""
    lines: list[tuple[str, int]] = []
    cur: list[str] = []
    pos = 0
    cr_pos: int | None = None  # Cursor beim ersten CR einer Folge vor dem LF
    text_parts: list[tuple[str, Any]] = []
    i, n = 0, len(data)
    plain = bytearray()

    def flush_plain() -> None:
        if plain:
            text_parts.append(("t", plain.decode("utf-8", errors="replace")))
            plain.clear()

    while i < n:
        b = data[i]
        if b == 0x1B and i + 1 < n and data[i + 1] == 0x5B:
            m = _CSI.match(data, i)
            if m is None:
                i += 2
                continue
            flush_plain()
            text_parts.append(("csi", (m.group(1).decode("ascii", "replace"), chr(m.group(3)[0]))))
            i = m.end()
            continue
        if b == 0x1B:  # OSC, SS3 und andere Folgen: überspringen
            flush_plain()
            i += _escape_len(data, i)
            continue
        plain.append(b)
        i += 1
    flush_plain()

    for kind, val in text_parts:
        if kind == "csi":
            params, final = val
            num = _first_num(params)
            moved = True
            if final == "C":
                pos += max(num, 1)
            elif final == "D":
                pos = max(0, pos - max(num, 1))
            elif final == "G":
                pos = max(0, max(num, 1) - 1)
            elif final == "K":
                moved = False
                if num == 0:
                    del cur[pos:]
                elif num == 1:
                    for k in range(min(pos + 1, len(cur))):
                        cur[k] = " "
                else:
                    cur = []
            elif final == "P":
                moved = False
                del cur[pos:pos + max(num, 1)]
            elif final == "@":
                moved = False
                cur[pos:pos] = [" "] * max(num, 1)
            else:
                moved = False
            if moved:
                cr_pos = None
            continue
        for ch in val:
            if ch == "\n":
                lines.append(("".join(cur), pos if cr_pos is None else cr_pos))
                cur, pos, cr_pos = [], 0, None
            elif ch == "\r":
                if cr_pos is None:
                    cr_pos = pos
                pos = 0
            elif ch == "\b":
                pos = max(0, pos - 1)
                cr_pos = None
            elif ord(ch) < 0x20 or ord(ch) == 0x7F:
                continue
            else:
                cr_pos = None
                while len(cur) < pos:
                    cur.append(" ")
                if pos < len(cur):
                    cur[pos] = ch
                else:
                    cur.append(ch)
                pos += 1
    lines.append(("".join(cur), pos))
    return lines


def _escape_len(data: bytes, i: int) -> int:
    """Länge einer Escape-Folge (nicht CSI) ab ``data[i] == ESC``."""
    n = len(data)
    if i + 1 >= n:
        return 1
    nxt = data[i + 1]
    if nxt == 0x5D:
        j = i + 2
        while j < n and data[j] != 0x07 and not (data[j] == 0x1B and j + 1 < n and data[j + 1] == 0x5C):
            j += 1
        if j >= n:
            return n - i
        return j - i + (1 if data[j] == 0x07 else 2)
    if nxt == 0x4F:
        return min(3, n - i)
    return 2


def _first_num(params: str) -> int:
    head = params.split(";", 1)[0].lstrip("?<=>!")
    return int(head) if head.isdigit() else 0


def echo_seen(typed: bytes, output: bytes) -> bool | None:
    """Erscheinen die getippten Zeilen in ``output`` wieder? ``None``: nichts Druckbares getippt.

    Jede getippte Zeile muss der Reihe nach in der gerenderten Ausgabe stehen. Kurze
    Zeilen (unter :data:`ANYWHERE_MIN` Zeichen) zählen nur, wenn sie eine angezeigte Zeile
    beenden (so endet ein Befehl, wenn Enter kommt) oder direkt vor dem Cursor stehen, als
    die Zeile endete (rechter Prompt, Vorschläge rechts vom Cursor); lange auch mitten in
    einer Zeile. Ein Tab ist ein Platzhalter für die Vervollständigung der Shell.
    """
    want = _typed_tokens(typed)
    if not want:
        return None
    screen = _render(output)
    row = 0
    for line in want:
        target = line.rstrip(" ")
        found = False
        while row < len(screen):
            shown, cursor = screen[row]
            row += 1
            if _line_shows(target, shown, cursor):
                found = True
                break
        if not found:
            return False
    return True


def _line_shows(target: str, shown: str, cursor: int) -> bool:
    """Steht die getippte Zeile ``target`` (mit Platzhaltern :data:`_TAB`) in der angezeigten
    Zeile ``shown``: am Zeilenende, direkt vor dem Cursor beim Zeilenende, oder (ab
    :data:`ANYWHERE_MIN` Zeichen) irgendwo?"""
    if target.count(_TAB) > _MAX_TABS:
        return False  # zu unklar: verdecken
    parts = target.split(_TAB)
    before_cursor = shown[:cursor] if 0 <= cursor <= len(shown) else shown
    shown, before_cursor = shown[-_MATCH_MAX:], before_cursor[-_MATCH_MAX:]
    if _ends_at(parts, shown.rstrip(), len(shown.rstrip())):
        return True
    if _ends_at(parts, before_cursor, len(before_cursor)):
        return True
    if len(target.replace(_TAB, "")) < ANYWHERE_MIN:
        return False
    return any(_ends_at(parts, shown, end) for end in _candidate_ends(parts, shown))


def _ends_at(parts: list[str], text: str, end: int) -> bool:
    """Endet die getippte Zeile genau bei ``end`` in ``text``? ``parts`` sind die getippten
    Stücke, zwischen zwei Stücken stand ein Tab. Ein Platzhalter steht für eine Ergänzung
    ohne Leerzeichen (ein vervollständigtes Wort); am Zeilenende darf ein Leerzeichen folgen
    (zsh nach einem Dateinamen). Von rechts nach links, jedes Stück so weit rechts wie
    möglich: linear, ohne reguläre Ausdrücke, denn die Zeile kommt vom Ziel."""
    limit = end
    last = parts[-1]
    if last:
        start = limit - len(last)
        if start < 0 or text[start:limit] != last:
            return False
        limit = start
    else:
        while limit > 0 and text[limit - 1] == " ":
            limit -= 1
    for part in reversed(parts[:-1]):
        if not part:
            continue  # Zeile begann mit einem Tab: links ist alles offen
        i = text.rfind(part, 0, limit)
        if i < 0 or " " in text[i + len(part):limit]:
            return False
        limit = i
    return True


def _candidate_ends(parts: list[str], text: str, cap: int = 512) -> list[int]:
    """Mögliche Enden für den Vergleich «irgendwo in der Zeile» (lange Eingaben): hinter jedem
    Vorkommen des letzten Stücks bzw. am Ende jedes Worts, wenn die Zeile mit einem Tab
    endete. Höchstens ``cap`` Stellen; mehr heisst verdecken (lieber zu viel)."""
    out: list[int] = []
    last = parts[-1]
    if last:
        i = text.find(last)
        while i >= 0 and len(out) < cap:
            out.append(i + len(last))
            i = text.find(last, i + 1)
    else:
        for k in range(1, len(text) + 1):
            if text[k - 1] != " " and (k == len(text) or text[k] == " "):
                out.append(k)
                if len(out) >= cap:
                    break
    return out


def output_window(chunks: Iterable[tuple[int, bytes]], start: int, out_end: int,
                  typed: bytes) -> bytes | None:
    """Ausgabe, in der das Echo einer Eingabe stehen müsste: ab ``start`` (Offset beim ersten
    getippten Byte) bis ``out_end`` und danach bis zum Zeilenende nach jeder getippten Zeile
    (höchstens :data:`TAIL_MAX` Bytes). ``chunks`` sind ``(stream_off, bytes)`` aus ``term.out``.
    ``None``, wenn ein Stück fehlt (Lücke, Pause): dann ist das Echo nicht prüfbar."""
    lines = max(1, typed.count(b"\r") + typed.count(b"\n") - typed.count(b"\r\n"))
    limit = out_end + TAIL_MAX
    buf = bytearray()
    pos = start
    for off, data in sorted(chunks, key=lambda c: c[0]):
        end = off + len(data)
        if end <= pos:
            continue
        if off > pos:
            break  # Lücke
        piece = data[pos - off: max(0, min(end, limit) - off)]
        buf += piece
        pos += len(piece)
        if pos >= limit:
            break
    if pos < out_end:
        return None
    head = bytes(buf[: out_end - start])
    tail = bytes(buf[out_end - start:])
    cut = 0
    for _ in range(lines):
        k = tail.find(b"\n", cut)
        if k < 0:
            cut = len(tail)
            break
        cut = k + 1
    return head + tail[:cut]


# --------------------------------------------------------------------------- Urteil, Anzeige


def classify(data: bytes, *, tty_no_echo: bool | None, output: bytes | None) -> InputVerdict:
    """Urteil für eine Eingabe (E104). ``output`` aus :func:`output_window` oder ``None``."""
    printable = sum(len(x) for x in typed_lines(data))
    if printable == 0:
        return InputVerdict(False, None, 0)
    if tty_no_echo:
        return InputVerdict(True, "tty_no_echo", printable)
    if output is None:
        return InputVerdict(True, "no_output", printable)
    if echo_seen(data, output) is False:
        return InputVerdict(True, "no_echo_seen", printable)
    return InputVerdict(False, None, printable)


def display_text(data: bytes, verdict: InputVerdict, *, reveal: bool = False) -> str:
    """Anzeige einer Eingabe: verdeckt :data:`MASK` (ohne Längenangabe), sonst der Text mit
    sichtbaren Steuerzeichen (``<ESC>``, ``<TAB>``), ohne das abschliessende Enter."""
    if verdict.hidden and not reveal:
        return MASK
    text = data.decode("utf-8", errors="replace")
    while text.endswith(("\r", "\n")):
        text = text[:-1]
    out = visible(text)
    return out if len(out) <= TEXT_MAX else out[: TEXT_MAX - 1] + "…"


def input_view(rec: Any, output: bytes | None, *, reveal: bool = False) -> dict[str, Any]:
    """JSON-taugliche Sicht auf ein ``term.input``-Event (``EventRecord``). Mit ``reveal`` steht
    der Klartext auch bei verdeckten Eingaben drin (``revealed = true``)."""
    h: Mapping[str, Any] = rec.header
    data = rec.body or b""
    verdict = classify(data, tty_no_echo=bool(h.get("no_echo")), output=output)
    return {
        "seq": rec.seq, "terminal_id": rec.terminal_id, "stream_off": h.get("stream_off"),
        "out_end": h.get("out_end"), "t_shim_ns": h.get("t_shim_ns"), "mono_ns": h.get("mono_ns"),
        "boot_id": rec.boot_id, "length": h.get("length", len(data)), "paste": bool(h.get("paste")),
        "redacted": rec.body is None, "hidden": verdict.hidden, "reason": verdict.reason,
        "revealed": bool(reveal and verdict.hidden), "text": display_text(data, verdict, reveal=reveal),
    }


# --------------------------------------------------------------------------- Journal


def _chunks(journal: Any, terminal_id: str, start: int, end: int) -> list[tuple[int, bytes]]:
    sl = getattr(journal, "stream_slice", None)
    if callable(sl):
        return list(sl(terminal_id, start, end))
    out = []
    for r in journal.iter_events(kinds=["term.out"], terminal_id=terminal_id):
        if r.body is None or r.stream_off is None:
            continue
        if r.stream_off < end and r.stream_off + len(r.body) > start:
            out.append((int(r.stream_off), r.body))
    return out


def _window_for(journal: Any, rec: Any) -> bytes | None:
    h = rec.header
    start, out_end = int(h.get("stream_off", 0)), int(h.get("out_end", 0))
    if rec.terminal_id is None:
        return None
    chunks = _chunks(journal, rec.terminal_id, start, out_end + TAIL_MAX)
    return output_window(chunks, start, out_end, rec.body or b"")


def collect_inputs(journal: Any, *, terminal_id: str | None = None, limit: int = 200,
                   before_seq: int | None = None) -> list[dict[str, Any]]:
    """Die neuesten ``limit`` Eingaben (älteste zuerst), verdeckt nach E104. Nie aufgedeckt."""
    limit = max(1, min(int(limit), 1000))
    keep: deque[Any] = deque(maxlen=limit)
    for rec in journal.iter_events(kinds=["term.input"], terminal_id=terminal_id):
        if before_seq is not None and rec.seq >= before_seq:
            break
        keep.append(rec)
    return [input_view(rec, _window_for(journal, rec)) for rec in keep]


def input_by_seq(journal: Any, seq: int, *, reveal: bool = False) -> dict[str, Any] | None:
    """Eine Eingabe nach ``seq`` (für das ausdrückliche Aufdecken). ``None``, wenn es kein
    ``term.input`` ist."""
    rec = journal.get(int(seq))
    if rec is None or rec.kind != "term.input":
        return None
    return input_view(rec, _window_for(journal, rec), reveal=reveal)
