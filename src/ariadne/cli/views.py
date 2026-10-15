"""Textansichten der CLI (Ersatz für die noch fehlende Web-Oberfläche).

Jeder Wert aus dem Daemon kann aus Zieldaten stammen und geht deshalb durch
``term_safe``. Secrets kommen vom Daemon nur maskiert.

Drei-Spuren-Regel (E42): Hosts und Services zeigen ``auto``, stille Werte nur als
Zähler; die Inbox enthält nur, was zu entscheiden ist, darüber die Summe der
stillen Werte. Die Zeitachse nennt pro Befehl die übernommenen Werte und den
Verweis für ``ariadne undo``.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from ariadne.termsafe import term_safe

__all__ = ["render_view", "render_search", "render_reparse", "render_confirm", "render_undo", "quiet_text",
           "STATE_TEXT", "SCOPE_TEXT"]

STATE_TEXT = {"candidate": "Kandidat", "auto": "auto", "confirmed": "bestätigt", "rejected": "verworfen"}
SCOPE_TEXT = {"in": "in Scope", "out": "ausserhalb", "excluded": "ausgeschlossen",
              "outside_window": "ausserhalb Zeitfenster", "unknown": "Scope unbekannt"}
KIND_TEXT = {"command": "Befehl", "segment": "Segment", "file": "Datei", "image": "Bild",
             "keystep": "Schritt"}
LEVEL_TEXT = {"high": "hoch", "medium": "mittel", "low": "niedrig"}
REASON_TEXT = {"ai": "KI-Wert", "ocr": "OCR-Wert", "important_heuristic": "heuristisch, wichtig",
               "offered": "vom Ziel angeboten", "suspect": "verdächtige Quelle"}
QUIET_TEXT = (("system_accounts", "+{n} Systemkonto", "+{n} Systemkonten"),
              ("out_of_scope", "{n} Wert ausserhalb des Scopes", "{n} Werte ausserhalb des Scopes"),
              ("heuristic", "{n} heuristischer Wert", "{n} heuristische Werte"),
              ("mentions", "{n} Erwähnung", "{n} Erwähnungen"),
              ("own_address", "{n} eigene Adresse (Kali)", "{n} eigene Adressen (Kali)"))
EXCLUDED_TEXT = {"own_address": ("eigene Adresse (Kali)", "eigene Adressen (Kali)"),
                 "out_of_scope": ("ausserhalb des Scopes", "ausserhalb des Scopes"),
                 "ai": ("KI- oder OCR-Wert", "KI- oder OCR-Werte"),
                 "low_confidence": ("mit niedriger Konfidenz", "mit niedriger Konfidenz"),
                 "conflict": ("im Widerspruch", "im Widerspruch"),
                 "context": ("mit unklarem Kontext", "mit unklarem Kontext"),
                 "merge": ("in einem Merge-Vorschlag", "in einem Merge-Vorschlag"),
                 "suspect": ("mit verdächtiger Quelle", "mit verdächtiger Quelle")}
MAX_ITEMS = 25


def s(value: Any, max_len: int = 120) -> str:
    return term_safe("" if value is None else value, max_len=max_len)


def _ts(ns: Any) -> str:
    if not isinstance(ns, int) or ns <= 0:
        return "--"
    return datetime.fromtimestamp(ns / 1e9).strftime("%m-%d %H:%M:%S")


def _hm(ns: Any) -> str:
    if not isinstance(ns, int) or ns <= 0:
        return "--:--"
    return datetime.fromtimestamp(ns / 1e9).strftime("%H:%M")


def quiet_text(counts: dict[str, Any] | None) -> str:
    """Zähler der stillen Spur: «+27 Systemkonten, 3 Werte ausserhalb des Scopes»."""
    parts = []
    for key, one, many in QUIET_TEXT:
        n = (counts or {}).get(key)
        if isinstance(n, int) and n > 0:
            parts.append((one if n == 1 else many).format(n=n))
    return ", ".join(parts)


def _service_line(sv: dict[str, Any]) -> str:
    port = f"{s(sv.get('port'), 6)}/{s(sv.get('proto'), 5)}"
    prod = " ".join(s(x, 60) for x in (sv.get("product"), sv.get("version")) if x)
    state = s(sv.get("state") or "?", 10)
    extra = f"  CVE: {', '.join(s(c, 20) for c in sv['cves'][:5])}" if sv.get("cves") else ""
    mark = {"confirmed": "", "auto": "  (auto)"}.get(str(sv.get("claim_state")), "  (Nebel)")
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
        quiet = quiet_text(h.get("quiet"))
        if quiet:
            out.append(f"  still: {quiet}")
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
    if kind in ("candidate_group", "decide_value"):
        flags = []
        if kind == "decide_value" and it.get("reason") in REASON_TEXT:
            flags.append(REASON_TEXT[str(it["reason"])])
        if it.get("from_target"):
            flags.append("vom Ziel angeboten")
        if it.get("suspect") and it.get("reason") != "suspect":
            flags.append("Injection-Verdacht")
        flag = f"  ({', '.join(flags)})" if flags else ""
        return (f"{s(it.get('ref'), 12)}  {s(it.get('subject'), 40)}  {s(it.get('predicate'), 24)} = "
                f"{s(it.get('value'), 60)}  [{LEVEL_TEXT.get(str(it.get('confidence')), '?')}, "
                f"{SCOPE_TEXT.get(str(it.get('scope')), 'Scope unbekannt')}]{flag}")
    p = it.get("payload") or {}
    if kind == "ctx_unknown" and p.get("path"):
        n = p.get("values") if isinstance(p.get("values"), int) else 0
        return (f"Kontext klären: Datei {s(p['path'], 120)} ({n} {'Wert' if n == 1 else 'Werte'} ohne Host; "
                "neu mit ariadne import PFAD --host HOST)")
    if kind in ("ctx_unknown", "ctx_suggestion"):
        term = str(p.get("terminal_id") or "")[-8:]  # Kurz-ID wie in ariadne status
        txt = f"Kontext klären: Terminal {s(term, 8)} ab Offset {s(p.get('from_off'), 12)}"
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


def _inbox(items: list[dict[str, Any]], full: bool, quiet: dict[str, Any] | None = None) -> list[str]:
    out: list[str] = []
    still = quiet_text(quiet)
    if still:
        out.append(f"Still (nie zum Klären): {still}")
    if not items:
        return out + ["Inbox leer."]
    for g in items:
        title = s(g.get("title"), 100)
        if g.get("kind") in ("candidate_group", "decide_value"):
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
        if g.get("kind") in ("candidate_group", "decide_value"):
            out.append(f"    sichere Werte bestätigen: ariadne confirm {s(g.get('ref'), 9)}")
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
        if e.get("type") == "command" and (e.get("adopted") or e.get("distrusted")):
            out.append("    " + _adopted_line(e))
    return out


def _adopted_line(e: dict[str, Any]) -> str:
    """«nmap 14:02: 21 Werte übernommen (ariadne undo 9f3c1a7e@1234)»."""
    title = str(e.get("title") or "")
    tool = s(title.split()[0] if title.split() else "Befehl", 32)
    ref = s(e.get("cmd_ref"), 64)
    if e.get("distrusted"):
        return f"{tool} {_hm(e.get('ts'))}: rückgängig gemacht (Befehl {ref})"
    n = e.get("adopted") if isinstance(e.get("adopted"), int) else 0
    word = "Wert" if n == 1 else "Werte"
    return f"{tool} {_hm(e.get('ts'))}: {n} {word} übernommen (ariadne undo {ref})"


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


def render_view(what: str, items: list[dict[str, Any]], *, full: bool = False,
                quiet: dict[str, Any] | None = None) -> list[str]:
    if what == "inbox":
        return _inbox(items, full, quiet)
    return _VIEWS[what](items, full)


def render_confirm(res: dict[str, Any]) -> list[str]:
    """Ergebnis von ``ariadne confirm``: bestätigt, und was nicht übernommen wurde (E88)."""
    out = [f"{s(res.get('confirmed', 0), 8)} Claim(s) bestätigt."]
    for c in (res.get("claims") or [])[:10]:
        out.append(f"  {s(c.get('subject'), 40)} {s(c.get('predicate'), 24)} = {s(c.get('value'), 60)} "
                   f"[{STATE_TEXT.get(str(c.get('state')), '-')}]")
    excluded = res.get("excluded") or {}
    parts = []
    for key, (one, many) in EXCLUDED_TEXT.items():
        n = excluded.get(key)
        if isinstance(n, int) and n > 0:
            parts.append(f"{n} {one if n == 1 else many}")
    if parts:
        hint = "; einzeln: ariadne confirm <claim>" if res.get("group") else ""
        out.append(f"Nicht übernommen: {', '.join(parts)}{hint}")
        for x in (res.get("excluded_sample") or [])[:5]:
            out.append(f"  {s(x.get('subject'), 40)} {s(x.get('predicate'), 24)} = {s(x.get('value'), 60)} "
                       f"({s(EXCLUDED_TEXT.get(str(x.get('reason')), (x.get('reason'),))[0], 40)})")
    return out


def render_undo(res: dict[str, Any]) -> list[str]:
    """Ergebnis von ``ariadne undo``."""
    return [f"Befehl {s(res.get('cmd_ref') or res.get('cmd_id'), 80)} rückgängig gemacht: "
            f"{s(res.get('rejected', 0), 8)} Werte verworfen, {s(res.get('weakened', 0), 8)} weitere "
            "verlieren diese Quelle."]


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
