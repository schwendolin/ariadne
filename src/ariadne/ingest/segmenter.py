"""Segmenter: Befehle, Kontextspannen und Einheiten eines Terminals (Architektur 3.5, 5.3, 5.4).

Reine Funktion :func:`compute_layout` über die Ereignisse eines Terminals
(``term.open``, ``term.mark``, ``term.ctx_snapshot``, ``term.gap``,
``term.close`` und die Entscheide ``d.ctx.*``). Sie ist billig und wird bei
jedem neuen Ereignis vollständig neu gerechnet; die teure Arbeit (Bytes
normalisieren) macht :mod:`ariadne.ingest.seg_stream`.

Regeln:

* Grenzen entstehen nur aus gültigen ``term.mark``-Events, nie aus OSC-133-Bytes
  im Strom. C zählt mit gültiger Nonce, D und A nur mit ``fg_shell``.
* Ein Befehl (``cmd_block``) läuft von C bis D. ``cmd_id`` ist
  ``ariadne.ids.cmd_id(terminal_id, C-Offset)``. Der Befehlstext kommt aus C
  (``cmd_expanded`` vor ``cmd_typed``) oder, bei bash vor 5.3, aus D. Flags:
  ``partial`` (REC begann mitten im Befehl, D ohne C), ``truncated`` (ohne D
  beendet), ``gap`` (Lücke im Strom).
* Der Kontext wird mit ``ariadne.ctxrules.ContextStack`` nachgespielt, sortiert
  nach (Offset, seq): Schnappschuss ersetzt den Stapel, C ->
  ``on_command_start``, D -> ``on_command_end``, ``d.ctx.push``/``pop``.
  ``d.ctx.set`` wirkt auf die Stufe, die bei ``from_off`` oben liegt (oder
  ``depth``), bis ``to_off`` bzw. bis die Stufe endet, auch rückwirkend; spätere
  Entscheide (seq) gewinnen. Liegt oben Kali, legt ``d.ctx.set`` wie im Daemon
  eine neue Stufe an.
* Einheiten sind maximale Bereiche mit gleichem (Befehl, Kontextspanne). Lokale
  Bytes vor einem Befehl (Prompt A..C, Reste nach dem letzten D) gehören zum
  nächsten Befehl derselben Spanne. Lokal ergibt ``command``, remote
  ``segment``; ohne Befehl immer ``segment``.
"""

from __future__ import annotations

import bisect
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ariadne.ctxrules import ContextStack, Stage, split_command
from ariadne.ids import cmd_id as make_cmd_id

__all__ = [
    "SegEvent",
    "CmdBlock",
    "CtxSpan",
    "UnitPlan",
    "Layout",
    "SEG_KINDS",
    "LOCAL_KINDS",
    "compute_layout",
    "event_offset",
    "unit_id_for",
]

SEG_KINDS = frozenset({
    "term.open", "term.mark", "term.ctx_snapshot", "term.gap", "term.close", "term.resize",
    "d.ctx.set", "d.ctx.push", "d.ctx.pop", "d.ctx.accept", "d.keystep.mark",
})
LOCAL_KINDS = frozenset({"local", "su"})
_INF = 1 << 62


@dataclass(frozen=True)
class SegEvent:
    seq: int
    kind: str
    off: int | None
    ts: int
    header: Mapping[str, Any]
    operator_id: str | None = None


def event_offset(kind: str, header: Mapping[str, Any]) -> int | None:
    """Stream-Offset eines Ereignisses (``from_off`` bei ``d.ctx.set``)."""
    key = "from_off" if kind == "d.ctx.set" else "stream_off"
    v = header.get(key)
    return int(v) if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else None


def unit_id_for(terminal_id: str, start: int) -> str:
    return f"u:{terminal_id}@{start}"


@dataclass
class CmdBlock:
    cmd_id: str
    terminal_id: str
    c_off: int
    prompt_off: int | None = None
    d_off: int | None = None
    end_off: int | None = None  # d_off oder der Punkt, an dem der Block abbrach
    text: str | None = None
    typed: str | None = None
    argv: tuple[str, ...] = ()
    cwd: str | None = None
    user: str | None = None
    exit: int | None = None
    pipestatus: tuple[int, ...] | None = None
    ts_start: int = 0
    ts_end: int | None = None
    flags: set[str] = field(default_factory=set)
    operator_id: str | None = None
    c_seq: int = 0
    d_seq: int | None = None
    ctx: tuple[dict[str, Any], ...] = ()  # Stapel vor dem C-Marker

    @property
    def closed(self) -> bool:
        return self.end_off is not None

    def row(self) -> dict[str, Any]:
        return {
            "cmd_id": self.cmd_id, "terminal_id": self.terminal_id, "c_off": self.c_off,
            "d_off": self.d_off, "prompt_off": self.prompt_off, "cmd_text": self.text,
            "cmd_typed": self.typed, "argv": json.dumps(list(self.argv), ensure_ascii=False),
            "cwd": self.cwd, "user": self.user, "exit_code": self.exit,
            "pipestatus": json.dumps(list(self.pipestatus)) if self.pipestatus is not None else None,
            "ts_start_ns": self.ts_start, "ts_end_ns": self.ts_end,
            "flags": json.dumps(sorted(self.flags)), "ctx": json.dumps(list(self.ctx), ensure_ascii=False),
        }


@dataclass
class CtxSpan:
    span_id: str
    terminal_id: str
    start: int
    end: int | None
    stage: dict[str, Any]  # oberste aktive Stufe
    stack: list[dict[str, Any]]
    stage_key: str

    @property
    def local(self) -> bool:
        return self.stage.get("kind") in LOCAL_KINDS

    def context(self) -> dict[str, Any]:
        """Stage-Dict für ``UnitView.context`` (plus Spanne und Terminal)."""
        d = {k: v for k, v in self.stage.items() if v is not None}
        d.update(span_id=self.span_id, stage_key=self.stage_key, terminal_id=self.terminal_id)
        return d

    def row(self) -> dict[str, Any]:
        st = self.stage
        return {
            "span_id": self.span_id, "terminal_id": self.terminal_id, "start_off": self.start,
            "end_off": self.end, "kind": st.get("kind"), "host": st.get("host"), "user": st.get("user"),
            "candidate": st.get("candidate"), "opened_at": st.get("opened_at"), "source": st.get("source"),
            "stage_key": self.stage_key, "stack": json.dumps(self.stack, ensure_ascii=False),
        }


@dataclass
class UnitPlan:
    unit_id: str
    kind: str
    terminal_id: str
    start: int
    end: int | None  # None = offen (bis zum aktuellen Strom-Ende)
    block: CmdBlock | None
    span: CtxSpan
    closed: bool  # Bereich ist strukturell abgeschlossen
    flags: set[str] = field(default_factory=set)

    @property
    def final(self) -> bool:
        return self.closed and (self.block is None or self.block.closed or self.kind == "segment")

    @property
    def cmd_id(self) -> str | None:
        return self.block.cmd_id if self.block is not None else None

    def sig(self) -> str:
        """Signatur aller Attribute, die ein Parser sieht. Änderung -> neu parsen."""
        b = self.block
        payload = [
            self.kind, self.start, self.end, self.closed, sorted(self.flags), self.span.context(),
            None if b is None else [b.cmd_id, b.text, b.cwd, b.exit, sorted(b.flags), b.d_off],
        ]
        raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()[:32]


@dataclass
class Layout:
    terminal_id: str
    blocks: list[CmdBlock]
    spans: list[CtxSpan]
    units: list[UnitPlan]
    rec_start: int | None
    stream_end: int
    closed: bool


# --------------------------------------------------------------------------- Befehle


def _int(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _blocks(tid: str, events: Sequence[SegEvent]) -> tuple[list[CmdBlock], int | None]:
    blocks: list[CmdBlock] = []
    cur: CmdBlock | None = None
    first_a: int | None = None
    since_start = False  # schon ein Marker seit Aufnahmebeginn?
    seg_start: int | None = None
    rec_start: int | None = None

    def close(b: CmdBlock, off: int, flag: str | None, ts: int) -> None:
        b.end_off = max(off, b.c_off)
        b.ts_end = ts
        if flag:
            b.flags.add(flag)

    for ev in events:
        h = ev.header
        if ev.kind in ("term.open", "term.ctx_snapshot"):
            if ev.off is not None:
                if rec_start is None:
                    rec_start = ev.off
                seg_start = ev.off
            since_start = cur is not None
            continue
        if ev.kind == "term.gap":
            if cur is not None:
                cur.flags.add("gap")
            continue
        if ev.kind == "term.close":
            if cur is not None and ev.off is not None:
                close(cur, ev.off, "truncated", ev.ts)
                cur = None
            continue
        if ev.kind != "term.mark" or ev.off is None:
            continue
        mark = h.get("mark")
        fg = h.get("fg_shell") is True
        if mark == "C":
            if cur is not None:
                close(cur, ev.off, "truncated", ev.ts)
            text = _str(h.get("cmd_expanded")) or _str(h.get("cmd_typed"))
            cur = CmdBlock(
                cmd_id=make_cmd_id(tid, ev.off), terminal_id=tid, c_off=ev.off, prompt_off=first_a,
                text=text, typed=_str(h.get("cmd_typed")), cwd=_str(h.get("cwd")), user=_str(h.get("user")),
                ts_start=ev.ts, operator_id=ev.operator_id, c_seq=ev.seq,
            )
            blocks.append(cur)
            first_a = None
            since_start = True
        elif mark == "D" and fg:
            b = cur
            if b is None and not since_start and seg_start is not None and ev.off > seg_start:
                b = CmdBlock(cmd_id=make_cmd_id(tid, seg_start), terminal_id=tid, c_off=seg_start,
                             ts_start=ev.ts, operator_id=ev.operator_id, c_seq=ev.seq, flags={"partial"})
                blocks.append(b)
            if b is not None:
                b.d_off = ev.off
                b.d_seq = ev.seq
                b.exit = _int(h.get("exit"))
                ps = h.get("pipestatus")
                if isinstance(ps, list | tuple) and all(_int(x) is not None for x in ps):
                    b.pipestatus = tuple(int(x) for x in ps)
                if b.text is None:
                    b.text = _str(h.get("cmd_expanded")) or _str(h.get("cmd_typed"))
                    b.typed = b.typed or _str(h.get("cmd_typed"))
                b.cwd = b.cwd or _str(h.get("cwd"))
                close(b, ev.off, None, ev.ts)
            cur = None
            first_a = None
            since_start = True
        elif mark == "A" and fg:
            if cur is not None:
                close(cur, ev.off, "truncated", ev.ts)
                cur = None
            if first_a is None:
                first_a = ev.off
            since_start = True
    for b in blocks:
        b.argv = tuple(split_command(b.text)) if b.text else ()
    return blocks, rec_start


# --------------------------------------------------------------------------- Kontext


class _Tracked:
    """``ContextStack`` mit stabilen IDs je Stufe (für Entscheide über Bereiche)."""

    def __init__(self) -> None:
        self.st = ContextStack()
        self.ids = [0]
        self._next = 1

    def _fresh(self) -> int:
        self._next += 1
        return self._next - 1

    def apply(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        before, ids = list(self.st.stages), list(self.ids)
        out = fn(*args, **kwargs)
        new = self.st.stages
        if len(new) == len(before):
            self.ids = ids
        elif len(new) == len(before) + 1 and all(a is b for a, b in zip(new, before, strict=False)):
            self.ids = ids + [self._fresh()]
        else:
            mapped = []
            for s in new:
                j = next((k for k, b in enumerate(before) if b is s), None)
                mapped.append(ids[j] if j is not None else self._fresh())
            self.ids = mapped
        return out

    def snapshot(self, stack: Iterable[Mapping[str, Any]]) -> None:
        self.st = ContextStack.from_snapshot([dict(s) for s in stack])
        self.ids = [self._fresh() for _ in self.st.stages]

    def top_index(self) -> int:
        for i in range(len(self.st.stages) - 1, -1, -1):
            if self.st.stages[i].state == "active":
                return i
        return 0

    def state(self) -> tuple[tuple[int, Stage], ...]:
        return tuple(zip(self.ids, self.st.stages, strict=True))


@dataclass
class _Overlay:
    seq: int
    target: int
    start: int
    end: int
    fields: dict[str, Any]


def _stage_dict(st: Stage) -> dict[str, Any]:
    return st.to_dict()


def _replay(tid: str, events: Sequence[SegEvent], blocks: Sequence[CmdBlock], rec_start: int | None,
            stream_end: int) -> tuple[list[tuple[int, tuple[tuple[int, Stage], ...]]], list[_Overlay]]:
    """Spielt den Stapel nach. Ergebnis: Zustände ab Offset und Bereichs-Entscheide."""
    by_c = {b.c_seq: b for b in blocks if "partial" not in b.flags}
    items: list[tuple[int, int, SegEvent]] = []
    for ev in events:
        if ev.off is None:
            continue
        if ev.kind in ("term.ctx_snapshot", "d.ctx.push", "d.ctx.pop", "d.ctx.set"):
            items.append((ev.off, ev.seq, ev))
        elif ev.kind == "term.mark":
            mark = ev.header.get("mark")
            if mark == "C" or (mark == "D" and ev.header.get("fg_shell") is True):
                items.append((ev.off, ev.seq, ev))
    items.sort(key=lambda x: (x[0], x[1]))
    tr = _Tracked()
    start = rec_start if rec_start is not None else 0
    states: list[tuple[int, tuple[tuple[int, Stage], ...]]] = [(start, tr.state())]
    overlays: list[_Overlay] = []
    for off, seq, ev in items:
        h = ev.header
        if ev.kind == "term.ctx_snapshot":
            stack = h.get("stack")
            if isinstance(stack, list | tuple):
                tr.snapshot(s for s in stack if isinstance(s, Mapping))
        elif ev.kind == "term.mark":
            if h.get("mark") == "C":
                b = by_c.get(seq)
                argv = list(b.argv) if b is not None else []
                if b is not None:
                    b.ctx = tuple(_stage_dict(s) for s in tr.st.stages)
                tr.apply(tr.st.on_command_start, argv, off)
            else:
                tr.apply(tr.st.on_command_end, _int(h.get("exit")), off)
        elif ev.kind == "d.ctx.push":
            tr.apply(tr.st.push, kind=_str(h.get("kind")) or "unknown", host=_str(h.get("host")),
                     user=_str(h.get("user")), offset=off, source="hotkey")
        elif ev.kind == "d.ctx.pop":
            tr.apply(tr.st.pop)
        elif ev.kind == "d.ctx.set":
            depth = _int(h.get("depth"))
            idx = tr.top_index() if depth is None else depth
            if idx <= 0 or idx >= len(tr.st.stages):
                if depth is None or depth == 0:
                    tr.apply(tr.st.push, kind=_str(h.get("kind")) or "unknown", host=_str(h.get("host")),
                             user=_str(h.get("user")), offset=off, source="hotkey")
            else:
                to = _int(h.get("to_off"))
                fields = {k: h[k] for k in ("host", "user", "kind") if _str(h.get(k))}
                fields["source"] = "decision"
                overlays.append(_Overlay(seq, tr.ids[idx], off, to if to is not None and to > off else _INF,
                                         fields))
        if states[-1][0] == off:
            states[-1] = (off, tr.state())
        else:
            states.append((off, tr.state()))
    overlays.sort(key=lambda o: o.seq)
    return states, overlays


def _spans(tid: str, states: list[tuple[int, tuple[tuple[int, Stage], ...]]], overlays: Sequence[_Overlay],
           stream_end: int) -> list[CtxSpan]:
    # Abschnitte [start, end) mit veränderbarem Stapel
    segs: list[list[Any]] = []
    for i, (off, state) in enumerate(states):
        end = states[i + 1][0] if i + 1 < len(states) else None
        if end is not None and end <= off:
            continue
        segs.append([off, end, [(sid, _stage_dict(st)) for sid, st in state]])
    for ov in overlays:
        out: list[list[Any]] = []
        for a, b, stack in segs:
            bb = _INF if b is None else b
            ids = [sid for sid, _ in stack]
            if ov.target not in ids or bb <= ov.start or a >= ov.end:
                out.append([a, b, stack])
                continue
            cuts = [a] + [x for x in (ov.start, ov.end) if a < x < bb] + [bb]
            for x, y in zip(cuts, cuts[1:], strict=False):
                part = stack
                if ov.start <= x < ov.end:
                    part = [(sid, ({**st, **ov.fields} if sid == ov.target else st)) for sid, st in stack]
                out.append([x, None if y == _INF else y, part])
        segs = out
    spans: list[CtxSpan] = []
    keys: list[tuple[int, str]] = []
    for a, b, stack in segs:
        top_i = 0
        for i in range(len(stack) - 1, -1, -1):
            if stack[i][1].get("state", "active") == "active":
                top_i = i
                break
        sid, top = stack[top_i]
        key = (sid, json.dumps(top, sort_keys=True))
        if spans and spans[-1].end == a and keys[-1] == key:
            spans[-1].end = b
            continue
        stage_key = "local" if top_i == 0 else f"{tid}@{top.get('opened_at', a)}/{top_i}"
        spans.append(CtxSpan(f"{tid}@{a}", tid, a, b, dict(top), [dict(st) for _, st in stack], stage_key))
        keys.append(key)
    if spans:
        spans[-1].end = None
    return spans


# --------------------------------------------------------------------------- Einheiten


def _units(tid: str, blocks: Sequence[CmdBlock], spans: Sequence[CtxSpan], gaps: Sequence[int],
           start: int, stream_end: int, closed: bool) -> list[UnitPlan]:
    if not spans or stream_end <= start:
        return []
    cuts = {start, stream_end}
    structural: set[int] = set()
    for b in blocks:
        for x in (b.c_off, b.end_off):
            if x is not None and start <= x <= stream_end:
                cuts.add(x)
                structural.add(x)
    for sp in spans:
        if start <= sp.start <= stream_end:
            cuts.add(sp.start)
            structural.add(sp.start)
    pts = sorted(cuts)
    span_starts = [sp.start for sp in spans]
    c_offs = [b.c_off for b in blocks]

    def span_at(x: int) -> CtxSpan:
        return spans[max(0, bisect.bisect_right(span_starts, x) - 1)]

    def block_at(x: int) -> CmdBlock | None:
        i = bisect.bisect_right(c_offs, x) - 1
        while i >= 0:
            b = blocks[i]
            if b.c_off <= x < (b.end_off if b.end_off is not None else _INF):
                return b
            if b.end_off is not None and b.end_off <= x:
                return None
            i -= 1
        return None

    def next_block(y: int) -> CmdBlock | None:
        i = bisect.bisect_left(c_offs, y)
        return blocks[i] if i < len(blocks) else None

    units: list[UnitPlan] = []
    for x, y in zip(pts, pts[1:], strict=False):
        if y <= x:
            continue
        sp = span_at(x)
        b = block_at(x)
        if b is None and sp.local:
            nb = next_block(y)  # lokale Bytes vor einem Befehl gehören zu ihm (Prompt, Reste)
            if nb is not None and (sp.end is None or sp.end >= nb.c_off):
                b = nb
        key = (b.cmd_id if b is not None else None, sp.span_id)
        if units and units[-1].end == x and (units[-1].cmd_id, units[-1].span.span_id) == key:
            units[-1].end = y
            continue
        kind = "command" if (b is not None and sp.local) else "segment"
        units.append(UnitPlan(unit_id_for(tid, x), kind, tid, x, y, b, sp, closed=False))
    for u in units:
        end = u.end if u.end is not None else stream_end
        u.closed = closed or end in structural
        if u.end == stream_end and not u.closed:
            u.end = None
        if u.block is not None:
            u.flags |= u.block.flags & {"partial", "truncated", "gap"}
        lo = bisect.bisect_left(gaps, u.start)
        if lo < len(gaps) and gaps[lo] < (u.end if u.end is not None else _INF):
            u.flags.add("gap")
    return units


def compute_layout(terminal_id: str, events: Sequence[SegEvent], stream_end: int, *,
                   closed: bool = False) -> Layout:
    """Befehle, Kontextspannen und Einheiten eines Terminals aus seinen Ereignissen.

    ``events`` sind die Segmenter-Ereignisse in seq-Reihenfolge, ``stream_end``
    das Ende der bisher empfangenen Bytes.
    """
    evs = sorted(events, key=lambda e: e.seq)
    blocks, rec_start = _blocks(terminal_id, evs)
    if rec_start is None:
        offs = [e.off for e in evs if e.off is not None]
        rec_start = min(offs) if offs else None
    start = rec_start if rec_start is not None else 0
    end = max([stream_end, start] + [b.end_off or 0 for b in blocks])
    states, overlays = _replay(terminal_id, evs, blocks, rec_start, end)
    spans = _spans(terminal_id, states, overlays, end)
    gaps = sorted(e.off for e in evs if e.kind == "term.gap" and e.off is not None)
    units = _units(terminal_id, blocks, spans, gaps, start, end, closed)
    return Layout(terminal_id, blocks, spans, units, rec_start, end, closed)
