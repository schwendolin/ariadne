"""Codes, Tokens und Bindung ohne Netz (R2, R5, R6, R7): austauschbare Uhr und Prozesse."""

from __future__ import annotations

import pytest

from ariadne.web.peer import PeerInfo, ProcInfo
from ariadne.web.sessions import CROCKFORD, AuthError, SessionStore, format_typed


class FakeClock:
    def __init__(self) -> None:
        self.wall = 1_790_000_000_000_000_000
        self.boot = 5_000_000_000

    def wall_ns(self) -> int:
        return self.wall

    def boot_ns(self) -> int:
        return self.boot

    def advance(self, seconds: float, *, wall: bool = True, boot: bool = True) -> None:
        if wall:
            self.wall += int(seconds * 1e9)
        if boot:
            self.boot += int(seconds * 1e9)


class Procs:
    def __init__(self) -> None:
        self.live: dict[int, ProcInfo] = {}

    def add(self, pid: int, comm: str = "firefox", start: int = 1) -> ProcInfo:
        info = ProcInfo(pid=pid, ppid=1, start=start, comm=comm)
        self.live[pid] = info
        return info

    def lookup(self, pid: int) -> ProcInfo | None:
        return self.live.get(pid)

    def alive(self, ref: ProcInfo) -> bool:
        now = self.live.get(ref.pid)
        return now is not None and now.start == ref.start


def _store(**kw):
    clock, procs = FakeClock(), Procs()
    store = SessionStore(clock=clock, proc_lookup=procs.lookup, alive=procs.alive, **kw)
    return store, clock, procs


def _peer(*pids: int) -> PeerInfo:
    return PeerInfo(uid=1000, inode=1, pids=tuple(pids))


def test_long_and_typed_codes_have_the_promised_form():
    store, _, _ = _store()
    code, ttl = store.issue_code(typed=False, via="local")
    assert len(code) == 22 and ttl == 60 and set(code) <= set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    typed, ttl = store.issue_code(typed=True, via="local")
    assert len(typed) == 10 and ttl == 120 and set(typed) <= set(CROCKFORD)
    assert format_typed(typed) == f"{typed[:5]}-{typed[5:]}"


def test_local_exchange_binds_to_the_peer_process():
    store, _, procs = _store()
    procs.add(4711, "firefox")
    code, _ = store.issue_code(typed=False, via="local")
    token, info = store.exchange(code, _peer(4711))
    assert info.origin == "local" and info.peer_pid == 4711 and info.peer_comm == "firefox"
    assert len(token) == 43
    assert store.authenticate(token, _peer(4711)) == info
    assert store.authenticate(token, _peer(4712)) is None  # anderer Prozess
    assert store.authenticate(token, _peer()) is None  # nicht lesbar: lokal nie
    assert store.authenticate(token + "x", _peer(4711)) is None
    assert store.authenticate("", _peer(4711)) is None


def test_typed_code_is_tolerant_but_single_use():
    store, _, procs = _store()
    procs.add(7)
    typed, _ = store.issue_code(typed=True, via="local")
    sloppy = format_typed(typed).lower().replace("0", "o").replace("1", "l")
    store.exchange(sloppy, _peer(7))
    with pytest.raises(AuthError) as exc:
        store.exchange(typed, _peer(7))
    assert exc.value.code == "unauthorized"


def test_local_code_from_unreadable_connection_is_refused_and_consumed():
    store, _, procs = _store()
    procs.add(7)
    code, _ = store.issue_code(typed=False, via="local")
    with pytest.raises(AuthError):
        store.exchange(code, _peer())  # Resolver liefert «nicht lesbar»
    with pytest.raises(AuthError):
        store.exchange(code, _peer(7))  # verbraucht


def test_sshd_binding_accepts_unreadable_or_the_sshd_itself():
    store, _, procs = _store()
    sshd = procs.add(900, "sshd-session")
    procs.add(4711, "curl")
    code, _ = store.issue_code(typed=False, via="sshd", sshd=sshd)
    token, info = store.exchange(code, _peer())
    assert info.origin == "sshd" and info.peer_pid == 900
    assert store.authenticate(token, _peer()) == info
    assert store.authenticate(token, _peer(900)) == info
    assert store.authenticate(token, _peer(4711)) is None  # lesbarer fremder Prozess
    # Tunnelende: sshd weg -> Sitzung endet bei der nächsten Prüfung
    del procs.live[900]
    assert store.check() == [info.session_id]
    assert store.authenticate(token, _peer()) is None and len(store) == 0


def test_sshd_code_from_foreign_readable_process_is_a_failure():
    store, _, procs = _store()
    sshd = procs.add(900, "sshd")
    procs.add(5)
    code, _ = store.issue_code(typed=False, via="sshd", sshd=sshd)
    with pytest.raises(AuthError):
        store.exchange(code, _peer(5))
    with pytest.raises(ValueError):
        store.issue_code(typed=False, via="sshd")


def test_pid_reuse_ends_the_session():
    store, _, procs = _store()
    procs.add(4711, start=10)
    code, _ = store.issue_code(typed=False, via="local")
    token, _ = store.exchange(code, _peer(4711))
    procs.add(4711, start=11)  # gleiche PID, anderer Prozess
    assert store.authenticate(token, _peer(4711)) is None


def test_five_failures_lock_all_codes_until_next_issue():
    store, clock, procs = _store()
    procs.add(7)
    good, _ = store.issue_code(typed=False, via="local")
    for _ in range(4):
        with pytest.raises(AuthError) as exc:
            store.exchange("falsch-falsch-falsch", _peer(7))
        assert exc.value.code == "unauthorized"
    with pytest.raises(AuthError):
        store.exchange("falsch-falsch-falsch", _peer(7))
    assert store.locked_out
    with pytest.raises(AuthError) as exc:
        store.exchange(good, _peer(7))
    assert exc.value.code == "rate_limited"
    fresh, _ = store.issue_code(typed=False, via="local")  # hebt die Sperre auf
    with pytest.raises(AuthError):
        store.exchange(good, _peer(7))  # alter Code bleibt ungültig
    store.exchange(fresh, _peer(7))


def test_failures_outside_the_window_do_not_add_up():
    store, clock, procs = _store()
    procs.add(7)
    for _ in range(4):
        with pytest.raises(AuthError):
            store.exchange("falsch-falsch-falsch", _peer(7))
    clock.advance(61)
    with pytest.raises(AuthError):
        store.exchange("falsch-falsch-falsch", _peer(7))
    assert not store.locked_out


def test_code_and_session_expiry_with_wall_or_boot_clock():
    store, clock, procs = _store(session_hours=12)
    procs.add(7)
    code, _ = store.issue_code(typed=False, via="local")
    clock.advance(61)
    with pytest.raises(AuthError):
        store.exchange(code, _peer(7))
    typed, _ = store.issue_code(typed=True, via="local")
    clock.advance(119)
    token, info = store.exchange(typed, _peer(7))
    assert info.expires_ns - info.created_ns == 12 * 3600 * 10**9
    clock.advance(12 * 3600 - 1, wall=True, boot=False)  # angehaltene VM: nur die Wanduhr springt
    assert store.authenticate(token, _peer(7)) is not None
    clock.advance(2, wall=True, boot=False)
    assert store.authenticate(token, _peer(7)) is None


def test_session_hours_are_capped_at_twelve():
    store, _, _ = _store(session_hours=48)
    assert store.session_hours == 12


def test_limits_on_open_codes_and_sessions():
    store, _, procs = _store(max_sessions=3)
    procs.add(7)
    codes = [store.issue_code(typed=False, via="local")[0] for _ in range(20)]
    assert store.open_codes == 16
    with pytest.raises(AuthError):
        store.exchange(codes[0], _peer(7))  # der älteste ist verdrängt
    ended: list[str] = []
    store.add_revoke_listener(ended.append)
    sids = [store.exchange(c, _peer(7))[1].session_id for c in codes[-4:]]
    assert len(store) == 3 and ended == [sids[0]]


def test_revoke_and_listing_never_contain_tokens():
    store, _, procs = _store()
    procs.add(7, comm="firefox")
    tokens = []
    for _ in range(2):
        code, _ = store.issue_code(typed=False, via="local")
        tokens.append(store.exchange(code, _peer(7))[0])
    listing = store.listing()
    assert [r["origin"] for r in listing] == ["local", "local"] and listing[0]["peer_comm"] == "firefox"
    dump = repr(listing) + repr(vars(store)) + repr(store._sessions) + repr(store._codes)
    for t in tokens:
        assert t not in dump
    ended: list[str] = []
    store.add_revoke_listener(ended.append)
    assert store.revoke(listing[0]["session_id"]) == 1
    assert store.revoke("gibtsnicht") == 0
    assert store.revoke() == 1 and len(ended) == 2
    assert store.authenticate(tokens[1], _peer(7)) is None
