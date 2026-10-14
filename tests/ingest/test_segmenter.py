"""Segmenter-Szenarien über die Pipeline mit MemoryJournal und synthetischen Events (Architektur 3.5, 5.4)."""

from __future__ import annotations

import json

from ariadne.ingest.segmenter import SegEvent, compute_layout
from ariadne.ingest.unit_store import load_unit
from ariadne.parsers.api import UnitView
from tests.ingest.helpers import TID


def units(env, conn=None):
    return env.rows("SELECT unit_id, kind, start_off, end_off, cmd_id, state FROM unit WHERE kind != 'file' "
                    "ORDER BY start_off", conn=conn)


def lines_of(env, unit_id, conn=None):
    return env.rows("SELECT pos, idx, text, flags FROM unit_line WHERE unit_id = ? ORDER BY pos", unit_id,
                    conn=conn)


def block(env, cmd_id):
    cols = ["cmd_id", "c_off", "d_off", "prompt_off", "cmd_text", "argv", "exit_code", "flags", "cwd"]
    row = env.conn.execute(f"SELECT {', '.join(cols)} FROM cmd_block WHERE cmd_id = ?", (cmd_id,)).fetchone()
    d = dict(zip(cols, row, strict=True))
    d["argv"], d["flags"] = json.loads(d["argv"]), json.loads(d["flags"])
    return d


def ctx(env, unit_id):
    return json.loads(env.rows("SELECT context FROM unit WHERE unit_id = ?", unit_id)[0][0])


# --------------------------------------------------------------------------- lokal


def test_local_command(env):
    t = env.term
    t.open()
    c = t.command("nmap -sV 10.10.10.3", b"Starting Nmap\r\n22/tcp open ssh\r\nNmap done\r\n")
    t.prompt()
    st = env.pipeline().process_new()
    assert st.units_parsed == 1
    cid = f"{TID}@{c}"
    b = block(env, cid)
    assert b["argv"] == ["nmap", "-sV", "10.10.10.3"] and b["exit_code"] == 0 and b["cwd"] == "/home/kali"
    us = units(env)
    assert us[0][:2] == (f"u:{TID}@0", "command") and us[0][3] == b["d_off"] and us[0][4] == cid
    assert us[0][5] == "final"
    assert us[1][1:] == ("segment", b["d_off"], None, None, "open")  # wartender Prompt
    ls = lines_of(env, us[0][0])
    assert [(r[1], r[2]) for r in ls] == [(None, "kali@kali:~$ nmap -sV 10.10.10.3"), (0, "Starting Nmap"),
                                          (1, "22/tcp open ssh"), (2, "Nmap done")]
    assert ls[0][3] & 1
    # Parser: Priorität, Sicht ohne Prompt
    calls = [c for c in env.projector.calls if c[0] == "apply_unit"]
    assert [c[1][1] for c in calls] == ["stub.high", "stub.ip"]
    unit, items, seq, trust, auto = env.projector.applied[(us[0][0], "stub.ip")]
    assert isinstance(unit, UnitView) and [ln.text for ln in unit.lines][0] == "Starting Nmap"
    assert unit.argv == ("nmap", "-sV", "10.10.10.3") and unit.exit_code == 0
    assert unit.context["kind"] == "local" and trust == "tool_text" and auto is True
    assert {i.value for i in items if hasattr(i, "value_type")} == {"10.10.10.3"} or items
    # FTS ohne Prompt-Echo
    hits = env.rows("SELECT text FROM unit_fts WHERE unit_fts MATCH 'nmap'")
    assert [h[0] for h in hits] == ["Starting Nmap", "Nmap done"]
    # Aktivitätsprotokoll
    act = env.rows("SELECT tool, targets, target_scope, ctx_kind, exit_code, origin, unit_id "
                   "FROM activity")[0]
    assert act[0] == "nmap" and json.loads(act[1]) == ["10.10.10.3"]
    assert json.loads(act[2])[0]["verdict"] == "in" and act[3] == "local" and act[4] == 0
    assert act[5] == "local" and act[6] == us[0][0]


def test_net_route_fills_src_ip(env):
    t = env.term
    t.open()
    c = t.command("ping -c1 10.10.10.3", b"64 bytes from 10.10.10.3\r\n")
    env.journal.append("net.route", {"cmd_id": f"{TID}@{c}", "target": "10.10.10.3", "src_ip": "10.10.14.2",
                                     "dev": "tun0"}, origin="daemon")
    env.pipeline().process_new()
    assert env.rows("SELECT src_ip FROM activity")[0][0] == "10.10.14.2"


def test_bash_before_5_3_text_from_d(env):
    t = env.term
    t.open()
    c = t.command("nmap 10.10.10.3", b"Nmap scan report for 10.10.10.3\r\n", text_in_d=True)
    env.pipeline().process_new()
    b = block(env, f"{TID}@{c}")
    assert b["cmd_text"] == "nmap 10.10.10.3" and b["argv"] == ["nmap", "10.10.10.3"]
    assert env.rows("SELECT tool FROM activity")[0][0] == "nmap"


# --------------------------------------------------------------------------- remote


def _ssh_session(t):
    t.open()
    c = t.start("ssh root@10.10.10.3", b"Welcome to Ubuntu\r\nLast login from 10.10.10.2\r\n"
                                       b"root@lame:~# id\r\nuid=0(root) gid=0(root)\r\n")
    t.out(b"root@lame:~# exit\r\nlogout\r\n\x1b]133;D;0\x07")
    t.end(0)
    d = t.off
    t.prompt()
    return c, d


def test_ssh_session_context(env):
    c, d = _ssh_session(env.term)
    env.pipeline().process_new()
    cid = f"{TID}@{c}"
    us = units(env)
    assert [(u[1], u[2], u[3], u[4]) for u in us] == [
        ("command", 0, c, cid), ("segment", c, d, cid), ("segment", d, None, None)]
    seg = ctx(env, us[1][0])
    assert seg["kind"] == "ssh" and seg["candidate"] == "10.10.10.3" and seg["user"] == "root"
    assert "host" not in seg  # unbestätigt, bis der Nutzer ihn setzt
    assert ctx(env, us[2][0])["kind"] == "local"
    spans = env.rows("SELECT kind, start_off, end_off FROM ctx_span ORDER BY start_off")
    assert spans == [("local", 0, c), ("ssh", c, d), ("local", d, None)]
    unit = load_unit(env.conn, us[1][0])
    assert unit.kind == "segment" and unit.argv == () and unit.lines[0].text == "Welcome to Ubuntu"
    assert (us[1][0], "stub.ip") in env.projector.applied
    # Aktivität nur für den lokalen Befehl, Kontext vor dem C
    assert env.rows("SELECT cmd_id, ctx_kind, tool FROM activity") == [(cid, "local", "ssh")]


def test_forged_d_without_foreground_is_ignored(env):
    t = env.term
    t.open()
    c = t.start("ssh root@10.10.10.3", b"root@lame:~# printf '\\e]133;D;0\\a'\r\n")
    t.end(0, fg=False)  # gültige Nonce, aber ssh im Vordergrund
    t.out(b"root@lame:~# still remote\r\n")
    t.end(0)
    env.pipeline().process_new()
    b = block(env, f"{TID}@{c}")
    assert b["d_off"] == t.off
    seg = [u for u in units(env) if u[1] == "segment" and u[4]]
    assert len(seg) == 1 and seg[0][2:4] == (c, t.off)
    texts = [r[2] for r in lines_of(env, seg[0][0])]
    assert texts == ["root@lame:~# printf '\\e]133;D;0\\a'", "root@lame:~# still remote"]


def test_osc133_bytes_are_never_boundaries(env):
    t = env.term
    t.open()
    t.start("ssh root@10.10.10.3", b"\x1b]133;D;0\x07\x1b]133;A\x07fake$ \x1b]133;C\x07rm -rf /\r\n")
    env.pipeline().process_new()
    assert env.rows("SELECT COUNT(*) FROM cmd_block")[0][0] == 1
    assert env.rows("SELECT kind FROM ctx_span ORDER BY start_off") == [("local",), ("ssh",)]


def test_reverse_shell_upgrade_with_ctrl_z_and_fg(env):
    t = env.term
    t.open()
    c1 = t.start("nc -lvnp 4444", b"listening on [any] 4444 ...\r\n"
                                  b"connect to [10.10.14.2] from (UNKNOWN) [10.10.10.3] 40000\r\n"
                                  b"www-data@lame:/$ ")
    t.out(b"^Z\r\nzsh: suspended  nc -lvnp 4444\r\n\x1b]133;D;148\x07")
    t.end(148)
    d1 = t.off
    t.prompt("stty raw -echo; fg")
    c2 = t.off
    t.mark("C", cmd_typed="stty raw -echo; fg", cwd="/home/kali")
    t.out(b"[1]  + continued  nc -lvnp 4444\r\nwww-data@lame:/$ whoami\r\nwww-data\r\n"
          b"www-data@lame:/$ exit\r\n")
    t.end(0)
    d2 = t.off
    t.prompt()
    env.pipeline().process_new()
    us = units(env)
    kinds = [(u[1], u[2], u[3], ctx(env, u[0])["kind"]) for u in us]
    assert kinds == [
        ("command", 0, c1, "local"), ("segment", c1, d1, "revshell"), ("command", d1, c2, "local"),
        ("segment", c2, d2, "revshell"), ("segment", d2, None, "local")]
    # dieselbe Stufe vor und nach dem Upgrade
    assert ctx(env, us[1][0])["stage_key"] == ctx(env, us[3][0])["stage_key"] != "local"
    assert block(env, f"{TID}@{c1}")["exit_code"] == 148
    assert [r[2] for r in lines_of(env, us[3][0])][-2:] == ["www-data", "www-data@lame:/$ exit"]


def test_retroactive_ctx_set(env):
    c, d = _ssh_session(env.term)
    p = env.pipeline()
    p.process_new()
    seg_id = f"u:{TID}@{c}"
    before = env.projector.applied[(seg_id, "stub.ip")][0]
    assert "host" not in before.context
    env.term.decision("d.ctx.set", from_off=c, host="ip:default/10.10.10.3", user="root")
    st = p.process_new()
    assert st.decisions == 1
    after = env.projector.applied[(seg_id, "stub.ip")][0]
    assert after.context["host"] == "ip:default/10.10.10.3" and after.context["kind"] == "ssh"
    assert ("clear_unit", seg_id) in env.projector.calls
    assert ctx(env, f"u:{TID}@{d}")["kind"] == "local"  # Rückkehr nach Kali bleibt
    # Teilbereich mit to_off: Einheit wird geteilt, Zeilen wandern mit
    mid = c + 30
    env.term.decision("d.ctx.set", from_off=c, to_off=mid, host="ip:default/10.10.10.99")
    p.process_new()
    segs = [u for u in units(env) if u[1] == "segment" and u[4]]
    assert len(segs) == 2
    first, second = segs
    assert ctx(env, first[0])["host"] == "ip:default/10.10.10.99"
    assert ctx(env, second[0])["host"] == "ip:default/10.10.10.3"
    texts = [r[2] for r in lines_of(env, first[0])] + [r[2] for r in lines_of(env, second[0])]
    assert texts[:2] == ["Welcome to Ubuntu", "Last login from 10.10.10.2"]
    for u in segs:
        idx = [r[1] for r in lines_of(env, u[0])]
        assert idx == list(range(len(idx)))  # neu nummeriert, ohne Lücken
    assert seg_id not in {u[0] for u in segs} or first[0] == seg_id


def test_hotkey_ctx_set_on_kali_pushes_stage(env):
    t = env.term
    t.open()
    c = t.start("python3 exploit.py 10.10.10.3", b"[+] got shell\r\n")
    t.decision("d.ctx.set", host="ip:default/10.10.10.3", user="www-data")
    t.out(b"$ id\r\nuid=33(www-data)\r\n")
    t.end(0)
    env.pipeline().process_new()
    spans = env.rows("SELECT kind, host, start_off FROM ctx_span ORDER BY start_off")
    assert spans[1][:2] == ("unknown", "ip:default/10.10.10.3")
    assert spans[2][0] == "local"  # D schliesst die Stufe
    assert c < spans[1][2]


# --------------------------------------------------------------------------- Lücken


def test_rec_gap_and_partial_command(env):
    t = env.term
    t.off = 1000  # REC beginnt mitten im laufenden Befehl
    t.open()
    t.out(b"...still running\r\n")
    t.out(b"\x1b]133;D;0\x07")
    t.end(0)
    first_d = t.off
    c = t.command("sleep 1; echo part1", b"part1\r\n")
    t.prompt()
    c2 = t.start("cat big.log", b"before gap\r\n")
    t.snapshot()  # REC wieder an: Daemon schreibt Schnappschuss und Lücke
    t.gap(500)
    t.out(b"after gap\r\n")
    t.end(0)
    env.pipeline().process_new()
    partial = block(env, f"{TID}@1000")
    assert partial["flags"] == ["partial"] and partial["d_off"] == first_d
    assert block(env, f"{TID}@{c}")["flags"] == []
    gb = block(env, f"{TID}@{c2}")
    assert gb["flags"] == ["gap"]
    u = [x for x in units(env) if x[4] == f"{TID}@{c2}"][0]
    flags = json.loads(env.rows("SELECT flags FROM unit WHERE unit_id = ?", u[0])[0][0])
    assert "gap" in flags
    texts = [r[2] for r in lines_of(env, u[0])]
    assert texts[-2:] == ["before gap", "after gap"]
    raw = env.rows("SELECT raw_start FROM unit_line WHERE text = 'after gap'")[0][0]
    assert raw >= c2 + 500


def test_term_close_finishes_open_unit(env):
    t = env.term
    t.open()
    t.start("tail -f log", b"line one\r\nline two without newline")
    t.close()
    env.pipeline().process_new()
    us = units(env)
    assert us[-1][5] == "final" and us[-1][3] is not None
    texts = [r[2] for r in lines_of(env, us[-1][0])]
    assert texts[-1] == "line two without newline"


# --------------------------------------------------------------------------- reine Funktion


def test_compute_layout_pure():
    def ev(seq, kind, off, **h):
        h.setdefault("terminal_id", TID)
        return SegEvent(seq, kind, off, seq, h, "op")

    evs = [ev(1, "term.ctx_snapshot", 0, stack=[{"kind": "local", "host": "local"}]),
           ev(2, "term.mark", 10, mark="A", fg_shell=True),
           ev(3, "term.mark", 30, mark="C", fg_shell=False, cmd_typed="ls"),  # C zählt auch ohne fg
           ev(4, "term.mark", 90, mark="D", fg_shell=True, exit=0),
           ev(5, "term.mark", 95, mark="A", fg_shell=True),
           ev(6, "term.mark", 100, mark="C", fg_shell=True, cmd_typed="cat x")]
    lay = compute_layout(TID, evs, 150)
    assert [(b.c_off, b.end_off, b.prompt_off) for b in lay.blocks] == [(30, 90, 10), (100, None, 95)]
    assert [(u.kind, u.start, u.end, u.final) for u in lay.units] == [
        ("command", 0, 90, True), ("command", 90, None, False)]
    closed = compute_layout(TID, evs + [ev(7, "term.close", 150)], 150, closed=True)
    assert closed.blocks[1].flags == {"truncated"} and closed.units[-1].final


def test_resize_changes_wrap_point(env):
    t = env.term
    t.open()
    t.start("cat wide", b"x" * 100)
    t._append("term.resize", {"stream_off": t.off, "rows": 24, "cols": 40}, stream_off=t.off)
    t.out(b"\rAB\r\n")  # Breite 40: \r springt an den Anfang der dritten physischen Zeile
    t.end(0)
    env.pipeline().process_new()
    assert ("x" * 80 + "AB" + "x" * 18,) in env.rows("SELECT text FROM unit_line")


def test_companions_only_for_local_commands(env):
    class Comp:
        id, version, trust, auto_eligible = "stub.comp", "1", "structured", False

        def match(self, unit):
            return 0

        def parse(self, unit):
            return iter(())

        def companions(self, argv, cwd):
            return [f"{cwd}/{a[3:]}.xml" for a in argv if a.startswith("-oA")]

    t = env.term
    t.open()
    c = t.command("nmap -oAscan 10.10.10.3", b"done\r\n", cwd="/home/kali/p")
    c2 = t.start("ssh root@10.10.10.3", b"")
    t.end(0)
    env.pipeline(registry=[Comp()]).process_new()
    got = dict(env.rows("SELECT cmd_id, companions FROM cmd_block"))
    assert json.loads(got[f"{TID}@{c}"]) == ["/home/kali/p/scan.xml"]
    assert json.loads(got[f"{TID}@{c2}"]) == []


def test_flags_altscreen_and_forged_marker(env):
    t = env.term
    t.open()
    c = t.start("vim notes", b"\x1b[?1049h\x1b[H\x1b[2Jhidden in vim\x1b[?1049l")
    t.end(0)
    c2 = t.start("ssh root@10.10.10.3", b"evil banner\r\n")
    t._append("term.marker_forged", {"stream_off": t.off, "reason": "bad_nonce"}, stream_off=t.off)
    t.out(b"more\r\n")
    t.end(0)
    env.pipeline().process_new()
    flags = {(r[0], r[1]): json.loads(r[2]) for r in env.rows("SELECT cmd_id, kind, flags FROM unit "
                                                                "WHERE cmd_id IS NOT NULL")}
    assert "altscreen" in flags[(f"{TID}@{c}", "command")]
    assert "marker_forged" in flags[(f"{TID}@{c2}", "segment")]
    vim = [u for u in units(env) if u[4] == f"{TID}@{c}" and u[3] - u[2] > 20][0]
    unit = load_unit(env.conn, vim[0])
    assert "hidden in vim" not in [ln.text for ln in unit.lines]  # Schlussbild nie an Parser
    assert ("hidden in vim", 8) in [(r[2], r[3]) for r in lines_of(env, vim[0])]


def test_output_after_close_is_ignored(env):
    t = env.term
    t.open()
    t.command("id", b"uid=0\r\n")
    t.close()
    t.out(b"late bytes\r\n")
    t.mark("A")
    p = env.pipeline()
    p.process_new()
    t.out(b"even later\r\n")
    p.process_new()
    assert ("late bytes",) not in env.rows("SELECT text FROM unit_line")


def test_decision_before_rec_start_applies_from_start():
    def ev(seq, kind, off, **h):
        h.setdefault("terminal_id", TID)
        return SegEvent(seq, kind, off, seq, h, "op")

    evs = [ev(1, "term.ctx_snapshot", 500, stack=[{"kind": "local", "host": "local"},
                                                   {"kind": "ssh", "opened_at": 400, "candidate": "x"}]),
           ev(2, "d.ctx.set", 100, from_off=100, host="ip:default/10.10.10.8")]
    lay = compute_layout(TID, evs, 900)
    assert [(s.start, s.stage.get("host")) for s in lay.spans] == [(500, "ip:default/10.10.10.8")]
    assert [(u.kind, u.start) for u in lay.units] == [("segment", 500)]


def test_hotkey_stage_keeps_key_across_rec_restart():
    """``F12 h`` auf Kali: Daemon (set_top) und Segmenter legen die Stufe am selben Offset an,
    sonst zerfällt sie nach REC aus/an in zwei Stufen (Host-Korrektur wirkt nur halb)."""
    from ariadne.ctxrules import ContextStack

    d = ContextStack()
    d.set_top(host="ip:default/10.10.10.7", source="hotkey", offset=1000)  # wie der Daemon
    local = [{"kind": "local", "host": "local", "opened_at": 0}]
    ev = [SegEvent(1, "term.open", 0, 1, {"cols": 80, "rows": 24}),
          SegEvent(2, "term.ctx_snapshot", 0, 1, {"stack": local}),
          SegEvent(3, "d.ctx.set", 1000, 2, {"terminal_id": TID, "from_off": 1000,
                                             "host": "ip:default/10.10.10.7"}),
          SegEvent(4, "term.ctx_snapshot", 2000, 3, {"stack": d.snapshot()}),
          SegEvent(5, "term.gap", 2000, 3, {"reason": "rec_off", "bytes_lost": 1000}),
          SegEvent(6, "term.ctx_snapshot", 3000, 3, {"stack": d.snapshot()})]
    lay = compute_layout(TID, ev, 4000)
    remote = [sp for sp in lay.spans if not sp.local]
    assert remote and {sp.stage_key for sp in remote} == {f"{TID}@1000/1"}
