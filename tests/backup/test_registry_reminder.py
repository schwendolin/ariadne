"""Registry der Sicherungen und Hinweis nach ``ariadne stop`` (E91, Vertrag 3.5)."""

from __future__ import annotations

import json
import os
import stat

from ariadne.backup import reminder
from ariadne.backup.registry import MAX_ENTRIES, add_entry, latest, read_entries
from tests.backup.helpers import new_identity, write_recipients


def _add(paths, ts, projects=("lame",), target="stdout", **kw):
    return add_entry(paths, entry_id=f"id-{ts}", ts_utc=ts, projects=list(projects),
                     manifest_sha256="ab" * 32, target=target, **kw)


def test_registry_add_trim_mode_and_latest(paths):
    assert read_entries(paths) == [] and latest(paths) is None
    _add(paths, "2026-10-01T10:00:00Z")
    _add(paths, "2026-10-03T10:00:00Z", projects=("box",), target="file", path="/tmp/x.age")
    _add(paths, "2026-10-02T10:00:00Z")
    assert stat.S_IMODE(os.stat(paths.registry_file).st_mode) == 0o600
    assert latest(paths)["id"] == "id-2026-10-03T10:00:00Z"
    assert latest(paths, "lame")["id"] == "id-2026-10-02T10:00:00Z"
    assert latest(paths, "fehlt") is None
    for i in range(MAX_ENTRIES + 5):
        _add(paths, f"2026-11-01T10:{i // 60 % 60:02d}:{i % 60:02d}Z")
    entries = read_entries(paths)
    assert len(entries) == MAX_ENTRIES
    assert entries[-1]["id"].startswith("id-2026-11-01")


def test_registry_ignores_broken_file_and_entries(paths):
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    paths.registry_file.write_text("{kaputt")
    assert read_entries(paths) == []
    paths.registry_file.write_text(json.dumps({"format": "ariadne.backup-registry/1", "backups": [
        {"id": "a", "ts_utc": "nie", "projects": [], "target": "stdout"},
        {"id": "b", "ts_utc": "2026-10-01T10:00:00Z", "projects": ["x"], "target": "ftp"},
        {"id": "c", "ts_utc": "2026-10-01T10:00:00Z", "projects": ["x"], "target": "file", "path": "/p"},
    ]}))
    os.chmod(paths.registry_file, 0o600)
    assert [e["id"] for e in read_entries(paths)] == ["c"]
    _add(paths, "2026-10-02T10:00:00Z")  # kaputte Einträge fallen beim Schreiben weg
    assert [e["id"] for e in read_entries(paths)] == ["c", "id-2026-10-02T10:00:00Z"]


def test_reminder_lines(paths):
    stop = {"stopped": True, "slug": "lame", "since_utc": "2026-10-10T08:00:00Z"}
    lines = reminder.after_stop_lines(paths, stop)
    assert lines[0] == "Erinnerung: Noch keine Sicherung von lame (E91)."
    assert lines[1] == reminder.HOW and "Empfänger" in lines[2]
    _, r = new_identity()
    write_recipients(paths, r)
    assert len(reminder.after_stop_lines(paths, stop)) == 2  # Empfänger da: kein Zusatz

    _add(paths, "2026-10-09T20:00:00Z", projects=("box",))  # andere Projekte zählen nicht
    assert reminder.after_stop_lines(paths, stop)[0].startswith("Erinnerung: Noch keine Sicherung")
    _add(paths, "2026-10-09T21:00:00Z")
    assert reminder.after_stop_lines(paths, stop) == [
        "Erinnerung: Die letzte Sicherung (2026-10-09T21:00:00Z) ist älter als diese Session.", reminder.HOW]
    _add(paths, "2026-10-10T09:00:00Z")
    assert reminder.after_stop_lines(paths, stop) == ["Sicherung: ariadne backup"]
    # ohne Beginn der Session: Grundhinweis, sobald es eine Sicherung gibt
    no_since = {"slug": "lame", "since_utc": None}
    assert reminder.after_stop_lines(paths, no_since) == ["Sicherung: ariadne backup"]


def test_reminder_never_raises(paths, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("kaputt")

    monkeypatch.setattr("ariadne.backup.registry.latest", boom)
    assert reminder.after_stop_lines(paths, {"slug": "lame"}) == ["Sicherung: ariadne backup"]
    monkeypatch.undo()
    assert reminder.after_stop_lines(paths, None)[0].startswith("Erinnerung: Noch keine Sicherung")
    assert reminder.after_stop_lines(paths, "unsinn")  # type: ignore[arg-type]
