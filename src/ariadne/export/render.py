"""Markdown-Dateien des Exports aus den gesammelten Daten (Vorlagen ``cys`` und ``htb``).

Jeder Wert aus dem Projekt geht durch :func:`~ariadne.export.mdsafe.md_text`,
:func:`~ariadne.export.mdsafe.md_lines` oder :func:`~ariadne.export.mdsafe.code_block`. Dateinamen
entstehen nur aus internen Kennungen (Kurz-ID) und einem Slug aus ``[a-z0-9-]``. Links zeigen nur auf
Dateien dieses Exports; externe URLs, Bilder von aussen, HTML und Mermaid gibt es nicht.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ariadne.export.mdsafe import code_block, md_lines, md_text, short_id, slug
from ariadne.ingest.proj_phases import OMIT, PHASE_LABELS, PHASES

__all__ = ["render", "beleg_name", "host_name", "TEMPLATE_TITLES", "SEVERITY_LABELS"]

TEMPLATE_TITLES = {"cys": "Writeup nach dem Schema des Moduls Cybersecurity", "htb": "Writeup im HTB-Stil"}
SEVERITY_LABELS = {
    "critical": "Kritisch (Critical)",
    "high": "Hoch (High)",
    "medium": "Mittel (Medium)",
    "low": "Tief (Low)",
    "info": "Info (Informational)",
    None: "ohne Schwere",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STEP_LABELS = {"foothold": "Foothold", "privesc": "Privilege Escalation", "pivot": "Pivot", "loot": "Loot"}
_SCOPE = {"in": "im Scope", "out": "ausserhalb des Scopes", "excluded": "ausgeschlossen", "unknown": "unbekannt"}
_EV_STATE = {"ok": "gültig", "distrusted": "misstraut", "missing": "fehlt nach Reparse"}

_GOALS = {
    "recon": "Informationen über das Ziel sammeln, ohne es direkt anzugreifen: Adressen, Namen, Umfeld.",
    "scanning": "Erreichbare Hosts, offene Ports, Dienste und Versionen bestimmen und aufzählen.",
    "exploitation": "Eine Schwachstelle ausnutzen und ersten Zugriff auf ein Ziel erlangen.",
    "post": "Zugriff ausbauen: Rechte erweitern, Daten sichern, weitere Netze erreichen.",
    "reporting": "Ergebnisse, Findings und Massnahmen nachvollziehbar zusammenfassen.",
    "enumeration": "Dienste, Versionen und Angriffsfläche aufzählen.",
    "foothold": "Ersten Zugriff auf das Ziel erlangen.",
    "privesc": "Rechte auf dem Ziel erweitern.",
    "pivot": "Von einem Ziel aus weitere Netze oder Hosts erreichen.",
    "loot": "Flags, Hashes, Schlüssel und Zugangsdaten sichern.",
    "lessons": "Was hat funktioniert, was nicht, was nehme ich mit?",
}

_HINWEIS = (
    "> Erstellt von Ariadne. Werte aus dem Ziel sind entschärft (keine Links, kein HTML, Steuerzeichen "
    "sichtbar) und stehen als Text oder in Codeblöcken. Zeiten in UTC mit Millisekunden."
)


def beleg_name(unit_id: str, program: str | None) -> str:
    return f"{short_id(unit_id)}-{slug(program or 'beleg', 'beleg')}.md"


def host_name(host_id: str, label: str) -> str:
    return f"{short_id(host_id)}-{slug(label, 'host')}.md"


def _t(value: Any) -> str:
    return md_text("" if value is None else value)


def _link(path: str) -> str:
    """Link auf eine Datei dieses Exports (Name nur aus Kurz-ID und Slug, ohne Leerzeichen)."""
    return f"[{path}]({path})"


def _sev(f: Mapping[str, Any]) -> str:
    return SEVERITY_LABELS.get(f.get("severity"), "ohne Schwere")


def _refs(items: list[Mapping[str, Any]]) -> str:
    if not items:
        return "keine"
    return ", ".join(f"{_t(x['id'])} ({'Hypothese' if x.get('hypothesis') else 'belegt'})" for x in items)


def _program_of(beleg: Any) -> str | None:
    cmd = getattr(beleg, "command", None)
    if not cmd:
        return getattr(beleg, "kind", None)
    return cmd.split()[0] if cmd.split() else None


def render(data: Mapping[str, Any]) -> dict[str, str]:
    """Alle Markdown-Dateien: ``{relativer Pfad: Inhalt}``."""
    meta = data["meta"]
    template = meta["template"]
    files: dict[str, str] = {}
    belege = data["belege"]
    bnames = {uid: beleg_name(uid, _program_of(b)) for uid, b in belege.items()}

    # Hosts
    hnames: dict[str, str] = {}
    for h in data["hosts"]:
        name = host_name(h["host_id"], h["label"])
        hnames[h["host_id"]] = name
        files[f"Hosts/{name}"] = _host(h)

    files["00 Übersicht.md"] = _overview(data, hnames)
    files["01 Angriffspfad.md"] = _path(data, bnames)
    files["02 Writeup.md"] = _writeup(data, bnames)
    files["03 Findings.md"] = _findings(data, bnames)
    files["Credentials.md"] = _credentials(data)
    files["Zeitachse.md"] = _timeline(data, bnames)
    for uid, b in belege.items():
        files[f"Belege/{bnames[uid]}"] = _beleg(b)
    if data["images"]:
        files["Belege/Screenshots.md"] = _images(data)
    _ = template
    return files


def _overview(data: Mapping[str, Any], hnames: Mapping[str, str]) -> str:
    meta = data["meta"]
    hosts = data["hosts"]
    in_scope = [h for h in hosts if h["scope"] == "in"]
    services = sum(len(h["services"]) for h in in_scope)
    sev: dict[str, int] = {}
    for f in data["findings"]:
        sev[f.get("severity") or "none"] = sev.get(f.get("severity") or "none", 0) + 1
    out = [
        f"# Übersicht: {_t(meta['name'])}",
        "",
        _HINWEIS,
        "",
        "## Projekt",
        "",
        f"- Projekt: {_t(meta['slug'])} (Profil {_t(meta['profile'])})",
        f"- Vorlage: {_t(meta['template'])}, {TEMPLATE_TITLES.get(meta['template'], '')}",
        f"- Zeitraum: {_t(meta['period'][0] or '-')} bis {_t(meta['period'][1] or '-')}",
        f"- Export: {_t(meta['created_at'])}",
        f"- Kettenkopf des Journals: Event {meta['chain_seq']}, Hash {_t(meta['chain_hash'] or '-')}",
        "",
        "## Scope",
        "",
    ]
    out += [f"- im Scope: {_t(x)}" for x in meta["scope_include"]] or ["- im Scope: keine Angabe"]
    out += [f"- ausgeschlossen: {_t(x)}" for x in meta["scope_exclude"]]
    out += [
        "",
        "## Statistik",
        "",
        f"- Hosts im Scope: {len(in_scope)}, Dienste: {services}",
        f"- Hosts ausserhalb des Scopes oder unbekannt: {len(hosts) - len(in_scope)}",
        f"- Befehle: {len(data['commands'])}, Belege: {len(data['belege'])}",
        f"- Schlüsselschritte im Faden: {len(data['keysteps'])}",
        f"- Findings: {len(data['findings'])}"
        + (" (" + ", ".join(f"{SEVERITY_LABELS.get(k if k != 'none' else None)}: {v}"
                            for k, v in sorted(sev.items(), key=lambda kv: _SEV_ORDER.get(kv[0], 9))) + ")"
           if sev else ""),
        f"- Screenshots: {len(data['images'])}",
        "",
        "## Hosts",
        "",
    ]
    for h in hosts:
        out.append(f"- {_t(h['label'])} ({_SCOPE.get(h['scope'], _t(h['scope']))}): {_link('Hosts/' + hnames[h['host_id']])}")
    if not hosts:
        out.append("- keine Hosts")
    out += [
        "",
        "## Dateien",
        "",
        "- 01 Angriffspfad.md: der Faden, Schritt für Schritt",
        "- 02 Writeup.md: Gerüst nach Phasen",
        "- 03 Findings.md: Findings mit Schwere, Massnahme, ATT&CK und CVE",
        "- Credentials.md: " + ("im Klartext" if meta["klartext"] else "maskiert"),
        "- Zeitachse.md, Hosts, Belege, _ariadne/manifest.json (SHA-256 aller Dateien und Kettenköpfe)",
        "",
    ]
    if meta["klartext"]:
        out += ["## Achtung", "", "Dieser Export enthält Zugangsdaten des Ziels im Klartext. Nicht weitergeben.", ""]
    return "\n".join(out)


def _path(data: Mapping[str, Any], bnames: Mapping[str, str]) -> str:
    out = ["# Angriffspfad", "", _HINWEIS, "", "Der Faden: die markierten Schlüsselschritte in zeitlicher Folge.", ""]
    if not data["keysteps"]:
        out += ["Noch keine Schlüsselschritte markiert (im Terminal F12 k oder ariadne mark).", ""]
    for i, k in enumerate(data["keysteps"], 1):
        step = _STEP_LABELS.get(k["step"]) or _t(k["step"])
        out.append(f"## Schritt {i}: {step}")
        out.append("")
        out.append(f"- Host: {_t(k['host'] or '-')}")
        out.append(f"- Zeit: {_t(k['ts'] or '-')}")
        if k.get("note"):
            out.append(f"- Notiz: {_t(k['note'])}")
        b = data["belege"].get(k.get("unit_id")) if k.get("unit_id") else None
        if b is not None:
            out.append(f"- Beleg: {_link('Belege/' + bnames[b.unit_id])}")
            out.append("")
            out.append(code_block(b.command or b.kind))
        out.append("")
    return "\n".join(out)


def _writeup(data: Mapping[str, Any], bnames: Mapping[str, str]) -> str:
    meta = data["meta"]
    template = meta["template"]
    phases = PHASES[template]
    by_phase: dict[str | None, list[Mapping[str, Any]]] = {}
    for c in data["commands"]:
        if c["phase"] == OMIT:
            continue
        by_phase.setdefault(c["phase"], []).append(c)
    finding_units: dict[str, list[Mapping[str, Any]]] = {}
    for f in data["findings"]:
        for ev in f["evidence"]:
            for u in ev["units"]:
                finding_units.setdefault(u, []).append(f)
    out = [
        f"# {TEMPLATE_TITLES[template]}",
        "",
        _HINWEIS,
        "",
        "Gerüst: Ziel, Tools, ausgeführte Befehle, Erkenntnisse und Belege pro Phase. Die Zuordnung der "
        "Befehle schlagen Regeln vor; korrigieren mit dem Entscheid d.unit.phase (Dashboard oder "
        "ariadne export --phase).",
        "",
    ]
    for n, ph in enumerate(phases, 1):
        cmds = by_phase.get(ph, [])
        out += [f"## {n} {PHASE_LABELS[ph]}", "", "### Ziel", "", _GOALS[ph], "", "### Tools", ""]
        tools = sorted({c["program"] for c in cmds if c.get("program")})
        out += [", ".join(_t(x) for x in tools) if tools else "keine", "", "### Ausgeführte Befehle", ""]
        if not cmds:
            out += ["keine", ""]
        for i, c in enumerate(cmds, 1):
            src = "Entscheid" if c["source"] == "decision" else "Regel"
            out.append(f"{i}\\. {_t(c['ts'] or '-')}, {_t(c['context'])} (Zuordnung: {src})")
            out.append("")
            out.append(code_block(c["command"]))
            out.append("")
            if c["unit_id"] in bnames:
                out += [f"Beleg: {_link('Belege/' + bnames[c['unit_id']])}", ""]
        out += ["### Erkenntnisse", "", "*Eigene Erkenntnisse hier ergänzen.*", ""]
        related = {f["finding_id"]: f for c in cmds for f in finding_units.get(c["unit_id"], [])}
        for f in related.values():
            out.append(f"- Finding F{f['ordinal']}: {_t(f['title'])} ({_sev(f)})")
        if related:
            out.append("")
        if ph == "reporting":
            out += ["### Findings", ""]
            out += [f"- F{f['ordinal']} {_t(f['title'])}: {_sev(f)}" for f in _sorted(data["findings"])] or ["keine"]
            out += ["", "Details: 03 Findings.md", ""]
    rest = by_phase.get(None, [])
    if rest:
        out += ["## Nicht zugeordnet", "", "Keine Regel passt; Phase per Entscheid setzen.", ""]
        for c in rest:
            out.append(f"- {_t(c['ts'] or '-')}, {_t(c['context'])}: {_t(c['command'])}"
                       + (f" ({_link('Belege/' + bnames[c['unit_id']])})" if c["unit_id"] in bnames else ""))
        out.append("")
    return "\n".join(out)


def _sorted(findings: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    return sorted(findings, key=lambda f: (_SEV_ORDER.get(f.get("severity"), 9), f["ordinal"]))


def _findings(data: Mapping[str, Any], bnames: Mapping[str, str]) -> str:
    out = ["# Findings", "", _HINWEIS, "", "Schwere setzt nur der Mensch. ATT&CK und CVE gelten als Hypothese, "
           "bis sie mit einem gültigen Beleg als belegt markiert sind.", ""]
    if not data["findings"]:
        out += ["Keine Findings.", ""]
    for f in _sorted(data["findings"]):
        out += [
            f"## F{f['ordinal']} {_t(f['title'])}",
            "",
            f"- Schwere: {_sev(f)}",
            f"- Status: {'final' if f['status'] == 'final' else 'Entwurf'}",
            f"- Betroffen: {', '.join(_t(a) for a in f['affected']) or '-'}",
            f"- MITRE ATT&CK: {_refs(f['attack'])}",
            f"- CVE: {_refs(f['cves'])}",
            f"- Angelegt: {_t(f['created'] or '-')}, geändert: {_t(f['updated'] or '-')}",
            "",
            "### Beschreibung",
            "",
            md_lines(f["description"]) if f["description"].strip() else "keine",
            "",
            "### Massnahme",
            "",
            md_lines(f["remediation"]) if f["remediation"].strip() else "keine",
            "",
            "### Belege",
            "",
        ]
        if not f["evidence"]:
            out.append("- keine Belege")
        for ev in f["evidence"]:
            label = _t(ev["label"]) if ev.get("label") else "Logauszug"
            links = [f"{_link('Belege/' + bnames[u])}" + (f" Zeilen {rng[0]} bis {rng[1]}" if rng else "")
                     for u, rng in zip(ev["units"], ev["lines"], strict=False) if u in bnames]
            out.append(f"- {label} ({_EV_STATE.get(ev['state'], _t(ev['state']))}): " + (", ".join(links) or "ohne Logauszug"))
        out.append("")
    return "\n".join(out)


def _host(h: Mapping[str, Any]) -> str:
    out = [
        f"# Host {_t(h['label'])}",
        "",
        _HINWEIS,
        "",
        f"- Scope: {_SCOPE.get(h['scope'], _t(h['scope']))}",
        f"- Adressen: {', '.join(_t(a) for a in h['addresses']) or '-'}",
        f"- Namen: {', '.join(_t(a) for a in h['names']) or '-'}",
        f"- Betriebssystem: {_t(h['os'] or '-')}",
        f"- Zugriff: {_t(h['access'] or 'keiner')}, Wissen: {_t(h['knowledge'] or '-')}, Arbeitsstand: {_t(h['work'] or '-')}",
        "",
        "## Dienste",
        "",
    ]
    if not h["services"]:
        out += ["keine", ""]
        return "\n".join(out)
    out += ["| Port | Protokoll | Dienst | Produkt | Version | CVE (Hypothese) |", "|---|---|---|---|---|---|"]
    for s in h["services"]:
        out.append(
            f"| {_t(s['port'])} | {_t(s['proto'])} | {_t(s['name'] or '-')} | {_t(s['product'] or '-')} | "
            f"{_t(s['version'] or '-')} | {', '.join(_t(c) for c in s['cves']) or '-'} |"
        )
    out.append("")
    return "\n".join(out)


def _credentials(data: Mapping[str, Any]) -> str:
    klar = data["meta"]["klartext"]
    out = ["# Credentials", "", _HINWEIS, ""]
    if klar:
        out += ["**Klartext:** Dieser Export enthält Zugangsdaten des Ziels im Klartext (Profil lab, im "
                "Terminal bestätigt). Nicht weitergeben.", ""]
    else:
        out += ["Zugangsdaten des Ziels sind maskiert. Klartext nur im Profil lab mit "
                "ariadne export --klartext und Bestätigung im Terminal.", ""]
    if not data["credentials"]:
        out += ["Keine bekannten Zugangsdaten.", ""]
    for i, c in enumerate(data["credentials"], 1):
        out.append(f"## {i} {_t(c['kind'])}")
        out.append("")
        out.append(code_block(c["value"]) if klar else c["value"])
        out.append("")
    return "\n".join(out)


def _timeline(data: Mapping[str, Any], bnames: Mapping[str, str]) -> str:
    out = ["# Zeitachse", "", _HINWEIS, ""]
    if not data["timeline"]:
        out += ["Keine Einträge.", ""]
    kinds = {"command": "Befehl", "segment": "Segment", "file": "Datei", "keystep": "Schlüsselschritt", "image": "Bild"}
    for e in data["timeline"]:
        parts = [_t(e["ts"] or "-"), kinds.get(e["type"], _t(e["type"]))]
        if e.get("terminal"):
            parts.append(_t(e["terminal"]))
        parts.append(_t(e["context"]))
        line = "- " + ", ".join(parts) + ": " + _t(e["title"])
        if isinstance(e.get("exit"), int):
            line += f" (Exit {e['exit']})"
        if e.get("unit_id") in bnames:
            line += f" ({_link('Belege/' + bnames[e['unit_id']])})"
        out.append(line)
    out.append("")
    return "\n".join(out)


def _beleg(b: Any) -> str:
    out = [
        f"# Beleg {_t(short_id(b.unit_id))}",
        "",
        _HINWEIS,
        "",
        f"- Art: {_t(b.kind)}",
        f"- Zeit: {_t(b.started or '-')} bis {_t(b.ended or '-')}",
        f"- Terminal: {_t(b.terminal or '-')}" + (f" ({_t(b.tty)})" if b.tty else ""),
        f"- Kontext: {_t(b.context)}",
    ]
    if isinstance(b.exit_code, int):
        out.append(f"- Exit-Code: {b.exit_code}")
    if b.path:
        out.append(f"- Datei: {_t(b.path)}")
    if b.sha256:
        out.append(f"- SHA-256 der Datei: {_t(b.sha256)}")
    if b.chain_seq is not None:
        out.append(f"- Kettenkopf: Event {b.chain_seq}, Hash {_t(b.chain_hash)}")
    else:
        out.append("- Kettenkopf: nicht verfügbar")
    out.append(f"- Einheit: {_t(b.unit_id)}")
    if b.ranges:
        out.append("- Belegbereich: " + ", ".join(f"Zeilen {a} bis {z}" for a, z in b.ranges))
    out += ["", "## Befehl", "", code_block(b.command or "(kein Befehl)"), "", "## Ausschnitt", ""]
    if b.lines:
        width = len(str(b.lines[-1][0]))
        body = "\n".join(f"{n:>{width}} | {text}" for n, text in b.lines)
        out.append(code_block(body))
        note = f"{len(b.lines)} von {b.total_lines} Zeilen"
        if b.truncated:
            note += ", gekürzt; das ganze Log steht im Projekt"
        out += ["", note + ". Zeilennummern wie in der Belegansicht."]
    else:
        out.append("keine Ausgabe")
    out.append("")
    return "\n".join(out)


def _images(data: Mapping[str, Any]) -> str:
    out = ["# Screenshots", "", _HINWEIS, ""]
    for im in data["images"]:
        if im.get("data") is not None and im.get("sha256"):
            name = f"img/{slug(im['sha256'])[:16]}.png"
            out.append(f"- {_t(im['ts'] or '-')}: {_link(name)}")
        else:
            out.append(f"- {_t(im['ts'] or '-')}: Bild nicht exportiert (fehlt oder kein PNG)")
    out.append("")
    return "\n".join(out)
