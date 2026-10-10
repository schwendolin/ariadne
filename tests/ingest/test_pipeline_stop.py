"""Abbruch eines Durchgangs (``should_stop``): nichts wird halb übernommen."""

from __future__ import annotations

import pytest

from ariadne.ingest.db import get_watermark
from ariadne.ingest.pipeline import WATERMARK, Interrupted


def test_should_stop_rolls_back_and_next_run_resumes(env):
    stop = {"now": False}
    t = env.term
    t.open()
    t.command("nmap 10.10.10.5", b"21/tcp open ftp\r\n")
    t.command("id", b"uid=0(root)\r\n")
    pipe = env.pipeline(should_stop=lambda: stop["now"])
    stop["now"] = True
    with pytest.raises(Interrupted):
        pipe.process_new()
    assert get_watermark(env.conn, WATERMARK) == 0
    assert env.rows("SELECT count(*) FROM unit WHERE parsed_sig IS NOT NULL") == [(0,)]
    stop["now"] = False
    stats = pipe.process_new()
    assert stats.units_parsed >= 2 and get_watermark(env.conn, WATERMARK) > 0
