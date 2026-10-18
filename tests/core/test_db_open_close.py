"""Öffnen und Schliessen von SQLCipher-Verbindungen laufen prozessweit nacheinander
(``ariadne.crypto.db``): Die mitgelieferte SQLite nimmt beim Öffnen und beim Schliessen einer
WAL-Verbindung dieselben zwei Sperren in umgekehrter Reihenfolge (Deadlock im Fixture-Daemon der
Browsertests, Integration v0.1-Oberfläche)."""

from __future__ import annotations

import threading
import time

from ariadne.crypto import db


def test_open_db_returns_connection_whose_close_waits_for_the_lock(tmp_path):
    key = db.new_key()
    conn = db.open_db(tmp_path / "x.db", key)
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    ro = db.open_db(tmp_path / "x.db", key, readonly=True)
    assert isinstance(conn, db._Connection) and isinstance(ro, db._Connection)
    held, release = threading.Event(), threading.Event()

    def holder() -> None:
        with db._OPEN_CLOSE:
            held.set()
            release.wait(5)

    th = threading.Thread(target=holder)
    th.start()
    held.wait(5)
    timer = threading.Timer(0.3, release.set)
    timer.start()
    t0 = time.monotonic()
    ro.close()  # wartet, bis der andere Thread die Sperre freigibt
    waited = time.monotonic() - t0
    th.join(5)
    timer.join(5)
    conn.close()
    assert waited >= 0.25


def test_open_and_close_from_many_threads_do_not_hang(tmp_path):
    key = db.new_key()
    first = db.open_db(tmp_path / "s.db", key)
    first.execute("CREATE TABLE t (a)")
    first.commit()
    errors: list[BaseException] = []

    def worker() -> None:
        try:
            for _ in range(30):
                c = db.open_db(tmp_path / "s.db", key)
                c.execute("INSERT INTO t VALUES (1)")
                c.commit()
                c.close()
        except BaseException as exc:  # noqa: BLE001 - im Haupt-Thread melden
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert not any(t.is_alive() for t in threads)
    assert errors == []
    assert first.execute("SELECT count(*) FROM t").fetchone()[0] == 120
    first.close()
