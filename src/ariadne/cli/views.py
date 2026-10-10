"""Textansichten der CLI (Ersatz für die noch fehlende Web-Oberfläche).

Jeder Wert aus dem Daemon kann aus Zieldaten stammen und geht deshalb durch
``term_safe``. Secrets kommen vom Daemon nur maskiert.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from ariadne.termsafe import term_safe

__all__ = ["render_view", "render_search", "render_reparse", "STATE_TEXT", "SCOPE_TEXT"]

STATE_TEXT = {"candidate": "Kandidat", "auto": "auto", "confirmed": "bestätigt", "rejected": "verworfen"}
SCOPE_TEXT = {"in": "in Scope", "out": "ausserhalb", "excluded": "ausgeschlossen",
              "outside_window": "ausserhalb Zeitfenster", "unknown": "Scope unbekannt"}
KIND_TEXT = {"command": "Befehl", "segment": "Segment", "file": "Datei", "image": "Bild",
             "keystep": "Schritt"}
LEVEL_TEXT = {"high": "hoch", "medium": "mittel", "low": "niedrig"}
MAX_ITEMS = 25


def s(value: Any, max_len: int = 120) -> str:
    return term_safe("" if value is None else value, max_len=max_len)


def _ts(ns: Any) -> str:
    if not isinstance(ns, int) or ns <= 0:
        return "--"
    return datetime.fromtimestamp(ns / 1e9).strftime("%m-%d %H:%M:%S")


def _service_line(sv: dict[str, Any]) -> str:
    port = f"{s(sv.get('port'), 6)}/{s(sv.get('proto'), 5)}"
    prod = " ".join(s(x, 60) for x in (sv.get("product"), sv.get("version")) if x)
    state = s(sv.get("state") or "?", 10)
    extra = f"  CVE: {', '.join(s(c, 20) for c in sv['cves'][:5])}" if sv.get("cves") else ""
    mark = "" if sv.get("claim_state") in ("confirmed", "auto") else "  (Nebel)"
    return f"{port:<10} {state:<9} {s(sv.get('name') or '-', 16):<16} {prod}{extra}{mark}"


def _hosts(items: list[dict[str, Any]], full: bool) -> list[str]:
    if not items:
        return ["Keine Hosts."]
    out: list[str] = []
    for h in items:
        state = STATE_TEXT.get(str(h.get("claim_state")), s(h.get("claim_state") or "-", 20))
        scope = SCOPE_TEXT.get(str(h.get("scope")), "Scope unbekannt")
        label = "unbekannter Kontext" if h.get("placeholder") else s(h.get("label"), 80)
        out.append(f"{label}  [{state}, {scope}]  Wissen: {s(h.get('knowledge') or '-', 12)}  "
                   f"Zugriff: {s(h.get('access') or '-', 8)}  Arbeit: {s(h.get('work') or '-', 14)}  "
                   f"Fortschritt {s(h.get('progress') or 0, 2)}/5")
        details = []
        if h.get("os"):
            details.append(f"OS: {s(h['os'], 80)}")
        if h.get("names"):
            details.append("Namen: " + ", ".join(s(n, 60) for n in h["names"][:5]))
        if h.get("conflicts"):
            details.append(f"Konflikte: {s(h['conflicts'], 4)}")
        if details:
            out.append("  " + "   ".join(details))
        svcs = h.get("services") or []
        shown = svcs if full else svcs[:MAX_ITEMS]
        out += ["  " + _service_line(sv) for sv in shown]
        if len(svcs) > len(shown):
            out.append(f"  ... und {len(svcs) - len(shown)} weitere (--all)")
    return out


def _services(items: list[dict[str, Any]], full: bool) -> list[str]:
    if not items:
        return ["Keine Services."]
    return [f"{s(sv.get('host'), 40):<18} {_service_line(sv)}" for sv in items]


def _inbox_item(it: dict[str, Any]) -> str:
    kind = it.get("kind")
    if kind == "candidate_group":
        flags = []
        if it.get("from_target"):
            flags.append("vom Ziel angeboten")
        if it.get("suspect"):
            flags.append("Injection-Verdacht")
        flag = f"  ({', '.join(flags)})" if flags else ""
        return (f"{s(it.get('ref'), 12)}  {s(it.get('subject'), 40)}  {s(it.get('predicate'), 24)} = "
                f"{s(it.get('value'), 60)}  [{LEVEL_TEXT.get(str(it.get('confidence')), '?')}, "
                f"{SCOPE_TEXT.get(str(it.get('scope')), 'Scope unbekannt')}]{flag}")
    p = it.get("payload") or {}
    if kind in ("ctx_unknown", "ctx_suggestion"):
        txt = f"Kontext klären: Terminal {s(p.get('terminal_id'), 8)}… ab Offset {s(p.get('from_off'), 12)}"
        txt += f", Stufe {s(p.get('kind'), 12)}, {s(p.get('units'), 6)} Einheiten"
        if p.get("candidate"):
            txt += f", Kandidat aus argv: {s(p['candidate'], 60)}"
        if kind == "ctx_suggestion":
            txt += f"; Vorschlag: {s(p.get('reason'), 80)}"
        return txt
    if kind == "conflict":
        vals = ", ".join(s(v.get("value"), 40) for v in (p.get("values") or [])[:5])
        return f"Konflikt: {s(p.get('subject_label'), 40)} {s(p.get('predicate'), 24)}: {vals}"
    if kind == "merge_suggestion":
        ids = ", ".join(s(i, 40) for i in (p.get("identifiers") or [])[:5])
        return f"Zusammenführen? {ids} ({s(p.get('reason'), 80)})"
    if kind == "orphan_decision":
        return (f"Verwaister Entscheid {s(p.get('kind'), 24)} (seq {s(p.get('seq'), 10)}): "
                f"{s(p.get('reason'), 80)}")
    if kind == "mass_find":
        return f"Massenfund: {s(p.get('hosts'), 8)} Hosts, {s(p.get('hint'), 60)}"
    return s(kind, 40)


def _inbox(items: list[dict[str, Any]], full: bool) -> list[str]:
    if not items:
        return ["Inbox leer."]
    out: list[str] = []
    for g in items:
        title = s(g.get("title"), 100)
        if g.get("kind") == "candidate_group":
            sm = g.get("summary") or {}
            counts = (f"{s(sm.get('hosts', 0), 6)} Hosts, {s(sm.get('services', 0), 6)} Services, "
                      f"{s(sm.get('credentials', 0), 6)} Credentials; {s(sm.get('out_of_scope', 0), 6)} "
                      f"ausserhalb Scope, {s(sm.get('low_confidence', 0), 6)} niedrige Konfidenz")
            out.append(f"[{s(g.get('ref'), 9)}] {_ts(g.get('ts'))}  {title}  ({counts})")
        else:
            out.append(f"[{s(g.get('ref'), 9)}] {_ts(g.get('ts'))}  {title}")
        its = g.get("items") or []
        shown = its if full else its[:MAX_ITEMS]
        out += ["    " + _inbox_item(it) for it in shown]
        if len(its) > len(shown):
            out.append(f"    ... und {len(its) - len(shown)} weitere (--all)")
        if g.get("kind") == "candidate_group":
            out.append(f"    alle bestätigen: ariadne confirm {s(g.get('ref'), 9)}")
    return out


def _timeline(items: list[dict[str, Any]], full: bool) -> list[str]:
    if not items:
        return ["Zeitachse leer."]
    out = []
    for e in items:
        kind = KIND_TEXT.get(str(e.get("type")), s(e.get("type"), 10))
        line = f"{_ts(e.get('ts'))}  {kind:<8} {s(e.get('context'), 40):<28} "
        if e.get("type") == "keystep":
            line += s(e.get("title"), 20) + (f"  {s(e['note'], 80)}" if e.get("note") else "")
        elif e.get("type") == "segment":
            line += f"({s(e.get('lines'), 8)} Zeilen)"
        else:
            line += s(e.get("title"), 100)
        extra = []
        if e.get("exit") is not None:
            extra.append(f"exit {s(e['exit'], 6)}")
        if e.get("src_ip"):
            extra.append(f"Quelle {s(e['src_ip'], 40)}")
        if any(v != "in" for v in e.get("scope") or []):
            extra.append("Ziel ausserhalb Scope oder unbekannt")
        flags = [f for f in e.get("flags") or [] if f in ("partial", "truncated", "gap", "altscreen",
                                                          "marker_forged")]
        if flags:
            extra.append(", ".join(s(f, 16) for f in flags))
        if extra:
            line += f"  [{'; '.join(extra)}]"
        out.append(line)
    return out


def _keysteps(items: list[dict[str, Any]], full: bool) -> list[str]:
    if not items:
        return ["Noch keine Schlüsselschritte (F12 k oder ariadne mark)."]
    return [f"{s(k.get('ordinal'), 4)}. {_ts(k.get('ts'))}  {s(k.get('step'), 12):<9} "
            f"{s(k.get('host') or '-', 60)}" + (f"  {s(k['note'], 80)}" if k.get("note") else "")
            for k in items]


def _pending(items: list[dict[str, Any]], full: bool) -> list[str]:
    if not items:
        return ["Warteliste leer."]
    return [f"{_ts(p.get('ts'))}  {s(p.get('reason'), 24):<20} {s(p.get('path'), 200)}" for p in items]


_VIEWS: dict[str, Callable[[list[dict[str, Any]], bool], list[str]]] = {
    "hosts": _hosts, "services": _services, "inbox": _inbox, "timeline": _timeline,
    "keysteps": _keysteps, "pending": _pending,
}


def render_view(what: str, items: list[dict[str, Any]], *, full: bool = False) -> list[str]:
    return _VIEWS[what](items, full)


def render_search(items: list[dict[str, Any]]) -> list[str]:
    if not items:
        return ["Keine Treffer."]
    return [f"{_ts(it.get('ts'))}  {s(it.get('context'), 40):<28} {s(it.get('text'), 160)}" for it in items]


def render_reparse(d: dict[str, Any]) -> list[str]:
    out = [
        f"derived.db neu aufgebaut: {s(d.get('units'), 8)} Einheiten, "
        f"Claims vorher {s(d.get('claims_before'), 8)}, nachher {s(d.get('claims_after'), 8)}",
        f"Neu: {s(d.get('added'), 8)}, entfallen: {s(d.get('removed'), 8)}, "
        f"geändert: {s(d.get('changed'), 8)}, Parser-Fehler: {s(d.get('parse_failures'), 8)}",
    ]
    samples = (("Neu", "added_sample"), ("Entfallen", "removed_sample"), ("Geändert", "changed_sample"))
    for title, key in samples:
        for c in d.get(key) or []:
            out.append(f"  {title}: {s(c.get('subject'), 40)} {s(c.get('predicate'), 24)} = "
                       f"{s(c.get('value'), 60)} [{STATE_TEXT.get(str(c.get('state')), '-')}]")
    orphans = d.get("orphans") or []
    if orphans:
        out.append(f"Verwaiste Entscheide: {len(orphans)} (stehen in der Inbox)")
        for o in orphans:
            out.append(f"  {s(o.get('kind'), 24)} seq {s(o.get('seq'), 10)}: {s(o.get('reason'), 80)}")
    else:
        out.append("Verwaiste Entscheide: keine")
    return out
