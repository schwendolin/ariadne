"""Transport: HELLO, Bündelung, Zeitindex (OUTX), INPUT, gemeinsame seq, ACK, Resume, Gating, Überlauf."""

from __future__ import annotations

import select
import socket
import time

import pytest

from ariadne._shim import protocol as P
from ariadne._shim import transport as T
from ariadne._shim.ringbuf import MIN_CAPACITY, FrameRing
from tests.shim.fake_daemon import FakeDaemon

HELLO_KEYS = {"proto", "terminal_id", "tty", "shell", "term", "rows", "cols", "tmux_pane", "window_id",
              "shim_version", "pid", "display", "resume_from_seq"}


def hello() -> dict:
    return {"proto": 1, "terminal_id": "t1", "tty": "/dev/pts/9", "shell": "/bin/zsh", "term": "xterm",
            "rows": 24, "cols": 80, "tmux_pane": None, "window_id": None, "shim_version": "x",
            "pid": 1, "display": {}}


_MADE: list[T.Transport] = []


def make(path, cap=MIN_CAPACITY, **kw) -> T.Transport:
    t = T.Transport(str(path), "t1", hello, FrameRing(cap), **kw)
    _MADE.append(t)
    return t


@pytest.fixture(autouse=True)
def _close_transports():
    yield
    while _MADE:
        t = _MADE.pop()
        t.on_disconnect = None
        t.close()


def pump(t: T.Transport, cond, timeout=3.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        t.tick(time.monotonic())
        if t.sock is not None:
            t.on_writable()
            r, _, _ = select.select([t.sock], [], [], 0.02)
            if r:
                t.on_readable()
        else:
            time.sleep(0.02)
        if cond():
            return True
    return bool(cond())


@pytest.fixture
def sock_path(tmp_path_factory):
    return tmp_path_factory.mktemp("rt") / "ariadne" / "term.sock"


def test_hello_state_batching_and_ack(sock_path):
    with FakeDaemon(sock_path) as d:
        t = make(sock_path)
        assert t.try_connect(time.monotonic())
        assert pump(t, lambda: t.ready)
        h = d.hellos()[0]
        assert set(h) == HELLO_KEYS and h["resume_from_seq"] is None
        now = time.monotonic()
        t.add_out(b"abc", 0, 1, 2, now)
        t.add_out(b"def", 3, 1, 2, now)
        t.add_event("term.mark", {"stream_off": 6})
        t.add_out(b"x" * (100 * 1024), 6, 1, 2, now)
        t.flush_out()
        assert pump(t, lambda: len(d.frames(P.OUTX)) == 3 and not t.ring)
        seqs = [(r.type, r.obj[0] if r.type == P.OUTX else r.obj["seq"]) for r in d.frames()
                if r.type in (P.OUTX, P.EVENT)]
        assert seqs == [(P.OUTX, 1), (P.EVENT, 2), (P.OUTX, 3), (P.OUTX, 4)]
        assert d.frames(P.OUT) == []  # Protokoll v2: nur noch OUTX
        outs = [r.obj for r in d.frames(P.OUTX)]
        assert outs[0][1] == 0 and outs[0][4] == b"abcdef"
        assert outs[1][1] == 6 and len(outs[1][4]) == T.BATCH_BYTES
        assert outs[2][1] == 6 + T.BATCH_BYTES
        t.bye(0)
        assert pump(t, lambda: True) and t.sock is None


def test_out_batch_flushes_after_50ms(sock_path):
    with FakeDaemon(sock_path) as d:
        t = make(sock_path)
        t.try_connect(time.monotonic())
        pump(t, lambda: t.ready)
        t.add_out(b"hi", 0, 1, 1, time.monotonic())
        assert t.deadline() is not None
        assert pump(t, lambda: d.out_bytes() == b"hi", timeout=1.0)


def test_resend_after_reconnect(sock_path):
    d1 = FakeDaemon(sock_path, ack=False).start()
    t = make(sock_path)
    t.try_connect(time.monotonic())
    pump(t, lambda: t.ready)
    t.add_out(b"one", 0, 1, 1, 0.0)
    t.add_event("term.resize", {"stream_off": 3, "rows": 1, "cols": 1})
    assert pump(t, lambda: len(d1.frames(P.EVENT)) == 1)
    d1.stop()
    assert pump(t, lambda: t.sock is None)
    t.add_out(b"two", 3, 1, 1, 0.0)  # offline gepuffert
    t.flush_out()
    with FakeDaemon(sock_path) as d2:
        assert pump(t, lambda: t.try_connect(time.monotonic()), timeout=3.0)
        assert pump(t, lambda: d2.out_bytes() == b"onetwo" and not t.ring)
        assert d2.hellos()[0]["resume_from_seq"] == 1
        assert [r.obj["seq"] for r in d2.frames(P.EVENT)] == [2]


def test_nothing_sent_before_first_state(sock_path):
    sock_path.parent.mkdir(parents=True, mode=0o700)
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(str(sock_path))
    srv.listen(1)
    t = make(sock_path)
    t.add_event("term.resize", {"stream_off": 0, "rows": 1, "cols": 1})
    assert t.try_connect(time.monotonic())
    conn, _ = srv.accept()
    conn.settimeout(1.0)
    dec = P.FrameDecoder()
    pump(t, lambda: False, timeout=0.2)
    frames = dec.feed(conn.recv(65536))
    assert [f.type for f in frames] == [P.HELLO]
    conn.sendall(P.encode_json(P.STATE, {"rec": "on"}))
    pump(t, lambda: t.ready, timeout=1.0)
    pump(t, lambda: False, timeout=0.1)
    frames = dec.feed(conn.recv(65536))
    assert [f.type for f in frames] == [P.EVENT]
    conn.close()
    srv.close()


def test_drop_unacked_reports_first_offset(tmp_path):
    t = make(tmp_path / "none.sock")
    t.add_out(b"a" * 10, 100, 1, 1, 0.0)
    t.flush_out()
    t.add_out(b"b" * 10, 110, 1, 1, 0.0)
    assert t.drop_unacked() == 100
    assert not t.ring and t.pending_out() == 0


def test_overflow_produces_gap_event(tmp_path):
    t = make(tmp_path / "none.sock", cap=MIN_CAPACITY)
    chunk = b"z" * T.BATCH_BYTES
    off = 0
    for _ in range(3 * MIN_CAPACITY // T.BATCH_BYTES):
        t.add_out(chunk, off, 1, 1, 0.0)
        off += len(chunk)
    t.flush_out()
    assert t.gap_start == 0 and t.gap_bytes > MIN_CAPACITY
    lost = t.gap_bytes
    t.tick(0.0)
    assert t.gap_start is not None  # Puffer noch voll
    t.ring.release_upto(t.ring.last_seq - 4)
    t.tick(0.0)
    ev = P.decode_json(P.FrameDecoder().feed(t.ring.get(t.ring.last_seq))[0].payload)
    assert ev["kind"] == "term.gap" and ev["reason"] == "buffer_overflow"
    assert ev["bytes_lost"] == lost and ev["stream_off"] == 0


def test_overflow_reason_goes_with_hello(sock_path):
    """Der Daemon sieht den Offset-Sprung vor unserem term.gap: Grund schon im HELLO."""
    t = make(sock_path, cap=MIN_CAPACITY)
    chunk = b"z" * T.BATCH_BYTES
    for i in range(3 * MIN_CAPACITY // T.BATCH_BYTES):
        t.add_out(chunk, i * len(chunk), 1, 1, 0.0)
    t.flush_out()
    assert t.gap_start is not None
    with FakeDaemon(sock_path) as d:
        assert pump(t, lambda: t.try_connect(time.monotonic()))
        assert d.wait_for(lambda: d.hellos())[0]["gap_hint"] == "buffer_overflow"


def test_foreign_uid_rejected(sock_path, monkeypatch):
    with FakeDaemon(sock_path):
        monkeypatch.setattr(T.os, "getuid", lambda: 54321)
        t = make(sock_path)
        assert not t.try_connect(time.monotonic())
        assert t.sock is None


def test_no_daemon_is_cheap_and_throttled(tmp_path):
    t = make(tmp_path / "missing" / "term.sock")
    t0 = time.monotonic()
    assert not t.try_connect(100.0)
    assert time.monotonic() - t0 < 0.1
    assert t.deadline() == 100.0 + T.RECONNECT_S
    assert not t.try_connect(100.5)
    assert t.deadline() == 100.0 + T.RECONNECT_S


def _frames(t: T.Transport) -> list[P.Frame]:
    dec = P.FrameDecoder()
    out: list[P.Frame] = []
    for e in t.ring.entries():
        out += dec.feed(t.ring.get(e.seq))
    return out


def test_outx_time_index_keeps_1ms_reads(tmp_path):
    t = make(tmp_path / "none.sock")
    w0, m0 = 1_700_000_000_000_000_000, 5_000_000_000
    t.add_out(b"ab", 0, w0, m0, 0.0)
    t.add_out(b"cd", 2, w0 + 400_000, m0 + 400_000, 0.0)  # unter 1 ms: kein Eintrag
    t.add_out(b"ef", 4, w0 + 1_500_000, m0 + 1_500_000, 0.0)
    t.add_out(b"gh", 6, w0 + 2_000_000, m0 + 2_000_000, 0.0)  # 0,5 ms nach dem letzten Eintrag
    t.add_out(b"ij", 8, w0 + 9_000_000, m0 + 9_000_123, 0.0)
    t.flush_out()
    fr = P.decode_outx(_frames(t)[0].payload)
    assert (fr.t_wall_ns, fr.t_mono_ns, fr.data) == (w0, m0, b"abcdefghij")
    assert fr.tix == ((4, 1500), (8, 9000))
    from ariadne import events
    h = {"t_shim_ns": fr.t_wall_ns, "mono_ns": fr.t_mono_ns, "tix": fr.tix}
    assert events.body_time(h, 3) == (w0, m0)
    assert events.body_time(h, 5) == (w0 + 1_500_000, m0 + 1_500_000)
    assert events.body_time(h, 9) == (w0 + 9_000_000, m0 + 9_000_000)


def test_outx_split_at_batch_bytes_rebases_time(tmp_path):
    t = make(tmp_path / "none.sock")
    t.add_out(b"a" * 1000, 0, 100_000_000, 10_000_000, 0.0)
    t.add_out(b"b" * (T.BATCH_BYTES + 10), 1000, 105_000_000, 15_000_000, 0.0)  # Bündel voll
    frs = [P.decode_outx(f.payload) for f in _frames(t)]
    assert [len(f.data) for f in frs] == [T.BATCH_BYTES, 1010]
    assert frs[0].tix == ((1000, 5000),)
    # Das zweite Stück beginnt mitten im zweiten read(): dessen Zeit gilt
    assert (frs[1].stream_off, frs[1].t_wall_ns, frs[1].t_mono_ns, frs[1].tix) == (
        T.BATCH_BYTES, 105_000_000, 15_000_000, ())


def test_outx_flushes_before_index_overflows(tmp_path):
    t = make(tmp_path / "none.sock")
    for i in range(P.MAX_TIX + 5):
        t.add_out(b"x", i, i * 2_000_000, i * 2_000_000, 0.0)
    t.flush_out()
    frs = [P.decode_outx(f.payload) for f in _frames(t)]
    assert len(frs) == 2 and all(len(f.tix) <= P.MAX_TIX for f in frs)
    assert b"".join(f.data for f in frs) == b"x" * (P.MAX_TIX + 5)
    assert frs[1].t_mono_ns == frs[1].stream_off * 2_000_000


def test_input_after_out_shares_seq_and_flushes_out_first(tmp_path):
    t = make(tmp_path / "none.sock")
    t.add_out(b"$ ", 0, 1_000, 2_000, 0.0)
    seq = t.add_input(b"ls\r", 2, 2, 3_000, 4_000, ((2, 7),))
    t.add_input(b"\x1b[200~paste\x1b[201~", 5, 9, 5_000, 6_000, paste=True)
    frs = _frames(t)
    assert [f.type for f in frs] == [P.OUTX, P.INPUT, P.INPUT] and seq == 2
    i1, i2 = P.decode_input(frs[1].payload), P.decode_input(frs[2].payload)
    assert (i1.seq, i1.stream_off, i1.out_end, i1.data) == (2, 2, 2, b"ls\r")
    assert (i1.tix, i1.paste) == (((2, 7),), False)
    assert (i2.seq, i2.out_end, i2.paste) == (3, 9, True)
    assert all(e.stream_off is None for e in list(t.ring.entries())[1:])  # keine Ausgabe-Bytes
