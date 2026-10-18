"""Lagebild für den KI-Denkanstoss (Architektur 6.3): deterministisch aus der Projektion, nie Rohausgaben.

Das Modell sieht nur dieses Lagebild, keinen Rohtext. Inhalt: Hosts im Scope mit Zugriff und
Arbeitsstand, offene Dienste, Identitäten (Secrets immer ``***``), offene Klärungen, Faden
(Schlüsselschritte), erledigte und verworfene Denkanstösse. Ziel etwa 2000 Tokens (8000 Zeichen).

Zieldaten sind feindlich (E13). Darum hat jede Art von Wert einen eigenen, strengen Encoder:
IP-Adressen kanonisch über ``ipaddress``, Namen nur ``[A-Za-z0-9.-]``, Produkt und Version nur
``[A-Za-z0-9 ._+-]{1,40}``, alles andere wird ``<gekürzt>``. Bekannte Secret-Werte vom Ziel werden
vorher maskiert, eigene Secrets am Ende mit ``redact_for_exit`` ersetzt (E72). Die Daten stehen in
einer Hülle mit Zufalls-Nonce; Anweisungen stehen nur im System-Prompt (Architektur 6.4).

Die Kennungen ``H1``, ``S1``, ``C1``, ``K1``, ``R1`` des Lagebilds sind die einzigen erlaubten Belege
einer Antwort; :class:`Situation` hält die Zuordnung zu Host- und Dienst-Kennungen der Projektion.
"""

from __future__ import annotations

import ipaddress
import re
import secrets as _secrets
from dataclasses import dataclass, field
from typing import Any

from ariadne.rules import api as rules_api
from ariadne.rules.engine import evaluate
from ariadne.rules.text import mask_known

__all__ = ["Situation", "Ref", "build_situation", "CUT", "MAX_CHARS", "estimate_tokens"]

CUT = "<gekürzt>"
MAX_CHARS = 8000  # etwa 2000 Tokens
_HOSTS_MAX = 40
_SERVICES_PER_HOST = 30
_IDENT_MAX = 20
_KEYSTEPS_MAX = 15
_DONE_MAX = 20

_PRODUCT = re.compile(r"[A-Za-z0-9 ._+-]{1,40}")
_NAME = re.compile(r"[A-Za-z0-9.-]{1,253}")
_WORD = re.compile(r"[A-Za-z0-9._-]{1,32}")
_USER = re.compile(r"[A-Za-z0-9._@-]{1,64}")
_TITLE = re.compile(r"[0-9A-Za-zÄÖÜäöü .,:?()+-]{1,120}")
_SEC_MASK = "••••••••"


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


@dataclass(frozen=True)
class Ref:
    """Ziel einer Kennung des Lagebilds."""

    kind: str  # host | service | identity | keystep | suggestion
    host_id: str | None = None
    service_id: str | None = None
    claim_keys: tuple[str, ...] = ()


@dataclass
class Situation:
    text: str  # Inhalt der Datenhülle (ohne Hülle), schon redigiert
    nonce: str
    refs: dict[str, Ref]
    allowed_addrs: set[str]  # IPs und Namen aus dem Lagebild (Freitext darf nur diese nennen)
    masked: int = 0  # maskierte Secret-Werte vom Ziel plus ersetzte eigene Secrets
    own_labels: list[str] = field(default_factory=list)
    warnings: int = 0  # generische Funde von scan_outgoing (z. B. Private Keys)
    hosts_total: int = 0
    hosts_shown: int = 0

    @property
    def wrapped(self) -> str:
        return f'<daten id="D1" quelle="projektion" grenze="{self.nonce}">\n{self.text}\n</daten grenze="{self.nonce}">'

    @property
    def tokens_estimate(self) -> int:
        return estimate_tokens(self.wrapped)


class _Enc:
    """Encoder pro Senke «Lagebild»; zählt maskierte Werte."""

    def __init__(self, known: list[str]) -> None:
        self.known = sorted({k for k in known if k}, key=len, reverse=True)
        self.masked = 0

    def _mask(self, v: str) -> str:
        out = mask_known(v, self.known)
        if out != v:
            self.masked += 1
        return out

    def ip(self, v: Any) -> str:
        try:
            return str(ipaddress.ip_address(str(v)))
        except ValueError:
            return CUT

    def name(self, v: Any) -> str:
        s = self._mask(str(v or ""))
        return s if _NAME.fullmatch(s) else CUT

    def product(self, v: Any) -> str:
        s = self._mask(str(v or "")).strip()
        return s if _PRODUCT.fullmatch(s) else CUT

    def word(self, v: Any) -> str:
        s = self._mask(str(v or ""))
        return s if _WORD.fullmatch(s) else CUT

    def user(self, v: Any) -> str:
        s = self._mask(str(v or ""))
        if _SEC_MASK in s:
            return "***"
        return s if _USER.fullmatch(s) else CUT

    def title(self, v: Any) -> str:
        s = self._mask(str(v or "")).replace(_SEC_MASK, "***")
        return f"«{s}»" if _TITLE.fullmatch(s) else CUT


def _host_rows(conn: Any, ids: list[str]) -> dict[str, tuple[Any, ...]]:
    out: dict[str, tuple[Any, ...]] = {}
    for i in range(0, len(ids), 400):
        chunk = ids[i : i + 400]
        q = ",".join("?" * len(chunk))
        sql = f"SELECT host_id, access, work, os FROM v_host WHERE host_id IN ({q}) LIMIT 2000"  # noqa: S608
        for row in conn.execute(sql, chunk).fetchall():
            out[str(row[0])] = tuple(row)
    return out


def _safe_rows(conn: Any, sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
    try:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]
    except Exception:  # Tabelle fehlt in älteren Projektionen: Abschnitt bleibt leer
        return []


def build_situation(
    conn: Any,
    *,
    profile: str,
    redactor: Any,
    ai_done: list[tuple[str, str]] | None = None,
    nonce: str | None = None,
) -> Situation:
    """Lagebild über ``derived.db`` (nur lesend, mit Grenzen). ``ai_done``: (Zustand, Titel) früherer
    KI-Denkanstösse, die erledigt oder verworfen sind."""
    f, _built = evaluate(conn, profile=profile)
    enc = _Enc(list(f.known_secrets))
    refs: dict[str, Ref] = {}
    addrs: set[str] = set()
    lines: list[str] = []

    scope_in = sorted(a for a, v in f.ip_verdict.items() if v == "in")
    scope_names = sorted(n for n, v in f.name_verdict.items() if v == "in")
    lines.append(
        "SCOPE in: "
        + (" ".join([enc.ip(a) for a in scope_in[:20]] + [enc.name(n) for n in scope_names[:10]]) or "-")
    )
    for a in scope_in[:20]:
        addrs.add(enc.ip(a))

    hosts = [h for h in f.hosts.values() if h.eligible]
    hosts.sort(key=lambda h: (h.ip is None, h.ip or "", h.host_id))
    rows = _host_rows(conn, [h.host_id for h in hosts[:_HOSTS_MAX]])
    n_h = n_s = 0
    body: list[str] = []
    shown = 0
    for h in hosts[:_HOSTS_MAX]:
        hid = f"H{n_h + 1}"
        local: dict[str, Ref] = {hid: Ref("host", host_id=h.host_id)}
        local_addrs: set[str] = set()
        row = rows.get(h.host_id, (h.host_id, None, None, None))
        ip = enc.ip(h.ip) if h.ip else "-"
        if ip not in ("-", CUT):
            local_addrs.add(ip)
        _addrs, names = h.addr_names()
        name_txt = ""
        if names:
            nm = enc.name(names[0])
            if nm != CUT:
                local_addrs.add(nm.lower())
            name_txt = f" name={nm}"
        block = [
            f"{hid} ip={ip}{name_txt} zugriff={enc.word(row[1] or 'keiner')} "
            f"arbeit={enc.word(row[2] or 'offen')} os={enc.product(row[3]) if row[3] else '-'}"
        ]
        k = n_s
        for s in h.open_services[:_SERVICES_PER_HOST]:
            k += 1
            sid = f"S{k}"
            keys = tuple(
                c.claim_key
                for p in ("service.product", "service.version", "service.name")
                if (c := s.one(p)) is not None
            )
            local[sid] = Ref("service", host_id=h.host_id, service_id=s.service_id, claim_keys=keys)
            prod = s.value("service.product")
            ver = s.value("service.version")
            block.append(
                f"  {sid} {int(s.port)}/{enc.word(s.proto)} {enc.word(s.name) if s.name else '-'}"
                f" produkt={enc.product(prod) if prod else '-'} version={enc.product(ver) if ver else '-'}"
            )
        if sum(len(x) + 1 for x in body) + sum(len(x) + 1 for x in block) > MAX_CHARS * 0.6:
            break
        body.extend(block)
        refs.update(local)
        addrs.update(local_addrs)
        n_h += 1
        n_s = k
        shown += 1
    lines.extend(body)
    if len(hosts) > shown:
        lines.append(f"(weitere {len(hosts) - shown} Hosts im Scope nicht gezeigt)")

    # Identitäten: Name als Zieldatum, Secret immer maskiert
    idents = _safe_rows(
        conn, "SELECT entity_id, label FROM entity WHERE type = 'identity' ORDER BY entity_id LIMIT ?", (_IDENT_MAX,)
    )
    for i, (_eid, label) in enumerate(idents, 1):
        refs[f"C{i}"] = Ref("identity")
        lines.append(f"C{i} identitaet={enc.user(label)} secret=***")

    # Offene Klärungen (nur Zahlen pro Art)
    inbox = _safe_rows(conn, "SELECT kind, COUNT(*) FROM v_inbox GROUP BY kind ORDER BY kind LIMIT 20")
    if inbox:
        lines.append("OFFENE KLÄRUNGEN: " + ", ".join(f"{enc.word(k)}={int(n)}" for k, n in inbox))
    else:
        lines.append("OFFENE KLÄRUNGEN: keine")

    # Faden (Schlüsselschritte)
    host_ref = {r.host_id: k for k, r in refs.items() if r.kind == "host"}
    steps = _safe_rows(
        conn, "SELECT ordinal, step, entity_id FROM v_keystep ORDER BY ordinal LIMIT ?", (_KEYSTEPS_MAX,)
    )
    for ordinal, step, eid in steps:
        kid = f"K{int(ordinal)}"
        refs[kid] = Ref("keystep", host_id=eid if isinstance(eid, str) else None)
        lines.append(f"FADEN {kid} {enc.word(step)} {host_ref.get(eid, '-')}")

    # Erledigte und verworfene Denkanstösse (Regeln: Regel und Bezug; KI: Titel als Text)
    n_r = 0
    svc_ref = {r.service_id: k for k, r in refs.items() if r.kind == "service"}
    for state in ("done", "dismissed"):
        items, _t = rules_api.suggestions(conn, profile=profile, state=state, limit=_DONE_MAX)  # type: ignore[arg-type]
        for it in items:
            n_r += 1
            ref = svc_ref.get(it.get("service_id")) or host_ref.get(it.get("host_id")) or "-"
            word = "ERLEDIGT" if state == "done" else "VERWORFEN"
            lines.append(f"{word} R{n_r} {enc.word(it.get('rule_id'))} {ref}")
            refs[f"R{n_r}"] = Ref("suggestion")
    for state, title in (ai_done or [])[:_DONE_MAX]:
        n_r += 1
        word = "ERLEDIGT" if state == "done" else "VERWORFEN"
        lines.append(f"{word} R{n_r} KI {enc.title(title)}")
        refs[f"R{n_r}"] = Ref("suggestion")

    text = "\n".join(lines)
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS].rsplit("\n", 1)[0] + "\n(gekürzt)"
    red, labels = redactor.redact_for_exit(text) if redactor is not None else (text, [])
    text = str(red)
    warnings = 0
    if redactor is not None:
        try:
            _hits, warns = redactor.scan_outgoing(text)
            warnings = len(warns)
        except Exception:
            warnings = 0
    nonce = nonce or _secrets.token_hex(8)
    # Die Hülle kann nicht gebrochen werden (strenge Encoder); trotzdem: Nonce darf nicht vorkommen
    while nonce in text:
        nonce = _secrets.token_hex(8)
    return Situation(
        text=text,
        nonce=nonce,
        refs=refs,
        allowed_addrs=addrs,
        masked=enc.masked + len(labels),
        own_labels=list(labels),
        warnings=warnings,
        hosts_total=len(hosts),
        hosts_shown=shown,
    )
