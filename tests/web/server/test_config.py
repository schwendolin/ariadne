"""``[ui]`` aus config.toml (Vertrag 3.7, R1): Loopback-Pflicht, Port, Sitzungsdauer."""

from __future__ import annotations

import pytest

from ariadne.web.config import UiConfig, UiConfigError, load_ui, parse_ui


def _write(paths, text: str) -> None:
    paths.config_dir.mkdir(parents=True, exist_ok=True)
    paths.config_file.write_text(text, encoding="utf-8")


def test_defaults_without_file(paths):
    assert load_ui(paths) == UiConfig(enabled=True, bind="127.0.0.1", port=7330, session_hours=12)


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "192.168.56.102", "kali.local", "localhost", "127.0.0.2",
                                  "::ffff:127.0.0.1", " 127.0.0.1", "", "100.64.1.2"])
def test_bind_outside_loopback_is_an_error(paths, bind):
    _write(paths, f'[ui]\nbind = "{bind}"\n')
    with pytest.raises(UiConfigError) as exc:
        load_ui(paths)
    assert str(exc.value) == "ui.bind erlaubt nur 127.0.0.1 oder ::1 (nur Loopback)"  # ohne den Wert


def test_bind_wrong_type_is_an_error():
    with pytest.raises(UiConfigError):
        parse_ui({"bind": 127})


@pytest.mark.parametrize("port", [80, 1023, 65536, -1, "7330", 7330.0, True])
def test_invalid_port_is_an_error(port):
    with pytest.raises(UiConfigError):
        parse_ui({"port": port})


def test_valid_values(paths):
    _write(paths, '[ui]\nbind = "::1"\nport = 0\nsession_hours = 4\nenabled = false\n')
    assert load_ui(paths) == UiConfig(enabled=False, bind="::1", port=0, session_hours=4)


@pytest.mark.parametrize("hours", [0, 13, "12", 1.5])
def test_invalid_session_hours_fall_back(hours, caplog):
    cfg = parse_ui({"session_hours": hours})
    assert cfg.session_hours == 12
    assert str(hours) not in caplog.text.replace("session_hours", "")


def test_broken_or_symlinked_file_gives_safe_defaults(paths, tmp_path):
    _write(paths, "[ui\nbind = ")
    assert load_ui(paths) == UiConfig()
    paths.config_file.unlink()
    target = tmp_path / "other.toml"
    target.write_text('[ui]\nbind = "0.0.0.0"\n')
    paths.config_file.symlink_to(target)
    assert load_ui(paths) == UiConfig()  # Symlink wird nie gelesen
    assert parse_ui("kein dict") == UiConfig()
