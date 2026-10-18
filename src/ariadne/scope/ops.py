"""ctl-Operationen zum Scope (E129). ``daemon/core.py`` nimmt :data:`OPS` in seine Tabelle auf.

* ``scope.show``: Einschlüsse, Ausschlüsse, Zeitfenster, Version, Profil, Bestätigung «kein
  Kundenauftrag» und die letzten Änderungen (mit ``decision_id`` für Rückgängig).
* ``scope.change`` ``{action, entries?, decision_id?, reason?, origin?, not_customer?, dry_run?}``:
  ``action`` ist ``add``, ``remove``, ``exclude``, ``open``, ``close`` (E131, ohne ``entries``) oder
  ``revert`` (mit ``decision_id``; der Name
  ``op`` ist im ctl-Protokoll vergeben). Schreibt
  ``d.scope.update`` mit neuer Version und ``change``; der Commit-Hook der Auswertung lädt die
  Einstellungen neu und rechnet alles neu (Scope-Urteile, Drei-Spuren-Regel, Scope-Warnungen).
  ``dry_run`` zeigt nur, was geschähe (Rückfrage im Terminal mit dem genauen Eintrag).

Öffnen (E131) gilt wie ein öffentliches Ziel. Schliessen braucht einen Einschluss (``no_include``),
Öffnen bzw. Schliessen ohne Wirkung ist ``noop``.

Leitplanken wie beim Anlegen: Neue Einschlüsse ausserhalb der Lab-Allowlist brauchen die
Bestätigung «kein Kundenauftrag» (``d.lab.not_customer``); die gibt es nur im Terminal
(``not_customer: true`` mit Herkunft ``cli``). Im Profil customer ändert nur das Terminal den Scope.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from ariadne.daemon.ops_util import OpError
from ariadne.project.guardrails import LabAllowlist
from ariadne.project.service import GuardrailError
from ariadne.scope.change import (
    ScopeChangeError,
    plan_change,
    plan_revert,
    render_toml,
    scope_lists,
    scope_open,
)
from ariadne.store.api import AppendItem

if TYPE_CHECKING:
    from ariadne.daemon.core import Daemon
    from ariadne.project.service import OpenProject

__all__ = ["OPS", "history", "not_customer_confirmed"]

_HISTORY = 20
_ORIGINS = ("cli", "webui")


def not_customer_confirmed(p: OpenProject) -> bool:
    return any(True for _ in p.journal.iter_events(kinds=["d.lab.not_customer"]))


def history(p: OpenProject, limit: int = _HISTORY) -> list[dict[str, Any]]:
    """Die letzten Änderungen über ``ariadne scope`` bzw. das Dashboard, neueste zuerst."""
    recs = list(p.journal.iter_events(kinds=["d.scope.update"]))
    reverted = {
        str(r.header["change"].get("revert_of")): r.id
        for r in recs
        if isinstance(r.header.get("change"), dict) and r.header["change"].get("revert_of")
    }
    out: list[dict[str, Any]] = []
    for r in reversed(recs):
        ch = r.header.get("change")
        if not isinstance(ch, dict):
            continue
        out.append({
            "decision_id": r.id,
            "seq": r.seq,
            "version": r.header.get("version"),
            "ts_utc_ns": r.ts_utc_ns,
            "origin": r.origin,
            "op": ch.get("op"),
            "entries": list(ch.get("entries") or []),
            "include_added": list(ch.get("include_added") or []),
            "include_removed": list(ch.get("include_removed") or []),
            "exclude_added": list(ch.get("exclude_added") or []),
            "exclude_removed": list(ch.get("exclude_removed") or []),
            "open_before": ch.get("open_before") if isinstance(ch.get("open_before"), bool) else None,
            "open_after": ch.get("open_after") if isinstance(ch.get("open_after"), bool) else None,
            "revert_of": ch.get("revert_of"),
            "reverted_by": reverted.get(r.id),
        })
        if len(out) >= limit:
            break
    return out


def _windows(windows: list[Any]) -> list[dict[str, str]]:
    out = []
    for w in windows[:50]:
        if isinstance(w, dict):
            out.append({k: str(w.get(k)) for k in ("days", "from", "to", "tz") if w.get(k) is not None})
    return out


def show(p: OpenProject) -> dict[str, Any]:
    include, exclude, windows = scope_lists(p.settings)
    return {
        "slug": p.info.slug,
        "project_id": p.info.id,
        "profile": p.info.profile,
        "version": p.settings_version,
        "include": include,
        "exclude": exclude,
        "open": scope_open(p.settings),
        "windows": _windows(windows),
        "not_customer": not_customer_confirmed(p),
        "history": history(p),
    }


async def op_show(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    return show(d._require_project())


def _entries(args: dict[str, Any]) -> list[Any]:
    v = args.get("entries")
    if not isinstance(v, list):
        raise OpError("invalid", "entries muss eine Liste sein")
    return v


def _reason(args: dict[str, Any]) -> str | None:
    r = args.get("reason")
    if r is None:
        return None
    if not isinstance(r, str) or len(r) > 500:
        raise OpError("invalid", "reason: höchstens 500 Zeichen")
    return r or None


def _revert_source(p: OpenProject, did: Any) -> dict[str, Any]:
    if not isinstance(did, str) or not 1 <= len(did) <= 64:
        raise OpError("invalid", "decision_id fehlt")
    rec = p.journal.get_by_id(did)
    ch = rec.header.get("change") if rec is not None and rec.kind == "d.scope.update" else None
    if not isinstance(ch, dict):
        raise OpError("not_found", "Keine Scope-Änderung mit dieser decision_id")
    for r in p.journal.iter_events(kinds=["d.scope.update"]):
        c = r.header.get("change")
        if isinstance(c, dict) and c.get("revert_of") == did:
            raise OpError("conflict", "Diese Änderung ist schon rückgängig gemacht")
    return ch


async def op_change(d: Daemon, args: dict[str, Any]) -> dict[str, Any]:
    p = d._require_project()
    origin = args.get("origin", "cli")
    if origin not in _ORIGINS:
        raise OpError("invalid", "origin muss cli oder webui sein")
    if p.info.profile == "customer" and origin != "cli":
        raise OpError("policy", "Im Profil customer ändert nur das Terminal den Scope (ariadne scope)")
    op = args.get("action")
    dry = args.get("dry_run") is True
    reason = _reason(args)
    allow = LabAllowlist.from_config(d.paths.config_file)
    try:
        if op == "revert":
            did = args.get("decision_id")
            plan = plan_revert(p.settings, _revert_source(p, did), str(did), allow)
        elif op in ("add", "remove", "exclude"):
            plan = plan_change(p.settings, str(op), _entries(args), allow)
        elif op in ("open", "close"):  # E131: ohne entries
            if args.get("entries") not in (None, []):
                raise OpError("invalid", "open und close ohne entries")
            plan = plan_change(p.settings, str(op), None, allow)
        else:
            raise OpError("invalid", "action muss add, remove, exclude, open, close oder revert sein")
    except ScopeChangeError as exc:
        if exc.code == "no_include" or (exc.code == "noop" and op in ("open", "close")):
            raise OpError(exc.code, str(exc)) from None  # E131: eigene Codes (API 409)
        code = "conflict" if exc.code in ("noop", "not_listed", "last_include") else "invalid"
        raise OpError(code, str(exc)) from None
    if plan.opens and p.info.profile != "lab":  # E131: offener Scope nie im Profil customer
        raise OpError("policy", "Offener Scope gibt es nur im Profil lab, nie im Profil customer")
    need_nc = ((bool(plan.outside) or plan.opens) and p.info.profile == "lab"
               and not not_customer_confirmed(p))
    version = p.settings_version + 1
    res: dict[str, Any] = {**plan.view(), "version": version, "needs_not_customer": need_nc,
                           "dry_run": dry, "decision_id": None, "seq": None}
    if dry:
        return res
    if need_nc and not (origin == "cli" and args.get("not_customer") is True):
        if plan.opens:
            raise GuardrailError(
                "Offener Scope gilt wie ein öffentliches Ziel. Nur im Terminal mit der Bestätigung, "
                "dass es kein Kundenauftrag ist: ariadne scope open",
                list(plan.outside),
                hint="open",
            )
        raise GuardrailError(
            "Ziele ausserhalb der Lab-Allowlist. Nur im Terminal mit der Bestätigung, dass es kein "
            "Kundenauftrag ist: ariadne scope add <ziel> --not-customer",
            list(plan.outside),
        )
    text = render_toml(str(_last_toml(p)), plan.include, plan.exclude,
                       plan.open_after if plan.open_after != plan.open_before else None)
    header = {"version": version, "toml": text, "change": plan.change(reason)}
    if d.project is not p:
        raise OpError("project_changed", "Projekt wurde währenddessen gewechselt, nichts gespeichert")
    if need_nc:
        d.submit(AppendItem("d.lab.not_customer", {"scope_version": version}, origin="cli"))
    d.submit(AppendItem("d.scope.update", header, origin=origin))
    records = d.flush()
    rec = next((r for r in records
                if r.kind == "d.scope.update" and r.header.get("version") == version), None)
    if rec is None:
        raise OpError("internal", "Scope-Änderung nicht gespeichert")
    if p.settings_version != version:  # Commit-Hook der Auswertung fehlt (Tests ohne Auswertung)
        p.reload_settings()
    d._notify("scope", project_id=p.info.id, version=version)
    res.update(decision_id=rec.id, seq=rec.seq)
    return res


def _last_toml(p: OpenProject) -> str:
    last = None
    for rec in p.journal.iter_events(kinds=["d.scope.update"]):
        last = rec
    if last is None:
        raise OpError("project", "Projekt ohne Einstellungen")
    return str(last.header["toml"])


OPS: dict[str, Callable[[Daemon, dict[str, Any]], Any]] = {
    "scope.show": op_show,
    "scope.change": op_change,
}
