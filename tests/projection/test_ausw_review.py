"""Korrekturen aus den Reviews in der Projektion: entschiedene Widersprüche (R5) und das
Scope-Urteil der Sammelbestätigung bei Konten (R6)."""

from __future__ import annotations

from ariadne.ingest import queries
from ariadne.ingest.claims import conflict_key
from ariadne.parsers.api import Obs, Ref, Span
from tests.parsers.helpers import make_unit
from tests.projection.helpers import FakeScope, apply_items, claims, dec, new_projector, rows

SP = Span(0, 0)
H = Ref.ip("192.168.56.101")
S21 = Ref.service(H, "tcp", 21)
SCOPE = FakeScope(nets=["192.168.56.0/24"])


def _ftp_conflict(profile: str = "lab"):
    conn, p = new_projector(SCOPE, profile=profile)
    apply_items(p, make_unit("x", unit_id="u1", cmd_id="t@1"), [Obs(S21, "service.product", "vsftpd", SP)],
                journal_seq=10)
    apply_items(p, make_unit("x", unit_id="u2", cmd_id="t@2"), [Obs(S21, "service.product", "ProFTPD", SP)],
                journal_seq=20)
    p.rebuild()
    return conn, p


def _states(conn) -> dict[str, tuple[str, str, str | None]]:
    cs = claims(conn, "service.product")
    return {k[2]: (v["state"], v["lane"], v["lane_reason"]) for k, v in cs.items()}


def _shown(conn) -> str:
    (row,) = rows(conn, "SELECT product FROM v_service")
    return row[0]


def test_resolved_conflict_choice_wins_and_other_is_never_auto():
    for profile in ("lab", "customer"):
        conn, p = _ftp_conflict(profile)
        ck = conflict_key(S21.key, "service.product")
        vs = claims(conn, "service.product")[(S21.key, "service.product", "vsftpd")]
        p.apply_decision(dec(30, "d.conflict.resolve", conflict_key=ck, choice=vs["claim_key"]))
        p.rebuild()
        st = _states(conn)
        assert st["vsftpd"] == ("confirmed", "user", "resolved"), (profile, st)
        assert st["ProFTPD"] == ("candidate", "quiet", "resolved"), (profile, st)
        assert _shown(conn) == "vsftpd"  # nicht alphabetisch «ProFTPD»
        assert not [g for g in queries.inbox(conn) if g["kind"] == "conflict"]


def test_kept_open_conflict_is_never_auto():
    conn, p = _ftp_conflict()
    ck = conflict_key(S21.key, "service.product")
    p.apply_decision(dec(30, "d.conflict.resolve", conflict_key=ck, keep_open=True))
    p.rebuild()
    st = _states(conn)
    assert {v[:2] for v in st.values()} == {("candidate", "quiet")}
    assert {v[2] for v in st.values()} == {"kept_open"}


def test_stale_choice_leaves_conflict_open():
    conn, p = _ftp_conflict()
    ck = conflict_key(S21.key, "service.product")
    p.apply_decision(dec(30, "d.conflict.resolve", conflict_key=ck, choice="gibt-es-nicht"))
    p.rebuild()
    assert {v[1] for v in _states(conn).values()} == {"decide"}


def test_group_confirm_judges_accounts_by_their_host():
    """Befund R6: Konto auf einem Host im Scope ist nicht «ausserhalb des Scopes»."""
    conn, p = new_projector(SCOPE, profile="customer")
    acct = Ref.identity("local:ip:default/192.168.56.101", "msfadmin")
    out = Ref.identity("local:ip:default/10.9.9.9", "root")
    apply_items(p, make_unit("x", unit_id="u1", cmd_id="t@1"), [
        Obs(H, "host.state", "up", SP),
        Obs(acct, "identity.exists", True, SP),
        Obs(out, "identity.exists", True, SP),
    ])
    p.rebuild()
    group = next(g for g in queries.inbox(conn) if g["group_key"] == "unit:u1")
    plan = queries.resolve_confirm(conn, group["ref"])
    assert plan["excluded"]["out_of_scope"] == 1  # nur root auf 10.9.9.9
    keys = set(plan["keys"])
    assert claims(conn, "identity.exists")[(acct.key, "identity.exists", "true")]["claim_key"] in keys
