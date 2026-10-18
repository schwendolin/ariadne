"""Die gebaute Weboberfläche ist eingecheckt und vollständig (Etappe 4, Paket): ``index.html`` und alle
referenzierten Dateien liegen in ``src/ariadne/web/static``, der Build-Vermerk nennt jede Datei mit
ihrem Hash und den Hash der webui-Quellen, aus denen gebaut wurde. ``ariadne doctor`` meldet eine
fehlende, unvollständige, veränderte oder veraltete Oberfläche.

Schlägt ``test_build_matches_sources`` fehl, wurden webui-Quellen geändert, ohne neu zu bauen:
``scripts/build-ui.sh`` ausführen und den Build mit einchecken.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from ariadne.cli import doctor
from ariadne.cli.doctor import FAIL, OK, UI_MANIFEST, WARN, ui_check, ui_files, ui_refs, ui_source_hash

ROOT = Path(__file__).resolve().parents[2]
STATIC = ROOT / "src" / "ariadne" / "web" / "static"
WEBUI = ROOT / "webui"


def _manifest() -> dict:
    return json.loads((STATIC / UI_MANIFEST).read_text(encoding="utf-8"))


def test_index_and_every_referenced_asset_exist():
    assert (STATIC / "index.html").is_file()
    files = ui_files(STATIC)
    refs = ui_refs(STATIC)
    # Shell, Einstieg, Stile und die nachgeladenen Chunks (Cytoscape) müssen gefunden werden
    assert any(r.startswith("assets/index-") and r.endswith(".js") for r in refs)
    assert any(r.endswith(".css") for r in refs) and "favicon.svg" in refs
    assert refs <= set(files), sorted(refs - set(files))
    # keine Quelltextkarten, keine Punktdateien ausser dem Vermerk, nichts ausserhalb der festen Typen
    assert not any(n.endswith(".map") for n in files)
    assert not any(part.startswith(".") for n in files for part in n.split("/"))
    assert {Path(n).suffix for n in files} <= {".html", ".js", ".css", ".svg", ".png", ".woff2"}


def test_manifest_lists_exactly_the_built_files():
    m = _manifest()
    assert m["format"] == 1 and len(m["source_sha256"]) == 64
    assert m["files"] == ui_files(STATIC)


def test_build_matches_sources():
    """Der eingecheckte Build stammt aus dem aktuellen Quellstand von webui/."""
    assert _manifest()["source_sha256"] == ui_source_hash(WEBUI), "scripts/build-ui.sh ausführen"
    assert ui_check(STATIC, WEBUI).level == OK


def test_build_is_tracked_not_ignored():
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("kein Git-Checkout")
    for rel in ("src/ariadne/web/static/index.html", f"src/ariadne/web/static/{UI_MANIFEST}"):
        res = subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-q", rel], capture_output=True, check=False
        )
        assert res.returncode == 1, f"{rel} ist in .gitignore ausgeschlossen"
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'artifacts = ["src/ariadne/web/static/**"]' in text


def test_source_hash_ignores_tests_and_follows_sources(tmp_path):
    web = tmp_path / "webui"
    (web / "src" / "lib").mkdir(parents=True)
    (web / "package.json").write_text("{}", encoding="utf-8")
    (web / "src" / "main.ts").write_text("export {};\n", encoding="utf-8")
    base = ui_source_hash(web)
    (web / "src" / "lib" / "x.test.ts").write_text("test\n", encoding="utf-8")
    (web / "tests").mkdir()
    (web / "tests" / "y.ts").write_text("y\n", encoding="utf-8")
    (web / "node_modules").mkdir()
    (web / "node_modules" / "z.js").write_text("z\n", encoding="utf-8")
    assert ui_source_hash(web) == base
    (web / "src" / "main.ts").write_text("export const a = 1;\n", encoding="utf-8")
    assert ui_source_hash(web) != base
    (web / "src" / "main.ts").write_text("export {};\n", encoding="utf-8")
    (web / "src" / "neu.ts").write_text("", encoding="utf-8")
    assert ui_source_hash(web) != base


def _copy(tmp_path: Path) -> tuple[Path, Path]:
    static = tmp_path / "static"
    shutil.copytree(STATIC, static, ignore=shutil.ignore_patterns("__pycache__"))
    web = tmp_path / "webui"
    for name in (
        "package.json",
        "package-lock.json",
        "index.html",
        "vite.config.ts",
        "svelte.config.js",
        "tsconfig.json",
    ):
        if (WEBUI / name).is_file():
            web.mkdir(exist_ok=True)
            shutil.copy2(WEBUI / name, web / name)
    shutil.copytree(WEBUI / "src", web / "src")
    shutil.copytree(WEBUI / "public", web / "public")
    return static, web


def test_doctor_reports_missing_changed_stale_and_unstamped(tmp_path):
    static, web = _copy(tmp_path)
    ok = ui_check(static, web)
    assert ok.level == OK and ok.title.startswith("Weboberfläche vorhanden"), ok
    # Wheel ohne Quellen: nur Vollständigkeit, Hinweis auf pipx
    assert ui_check(static, None, checkout=False).level == OK
    # veraltet: Quelle geändert
    main = web / "src" / "main.ts"
    main.write_text(main.read_text(encoding="utf-8") + "\n// geändert\n", encoding="utf-8")
    stale = ui_check(static, web)
    assert (stale.level, stale.title) == (WARN, "Weboberfläche veraltet")
    assert "scripts/build-ui.sh" in stale.detail
    # verändert: eine gebaute Datei weicht vom Vermerk ab
    css = next(static.glob("assets/*.css"))
    css.write_bytes(css.read_bytes() + b"\n")
    bad = ui_check(static, web)
    assert (bad.level, bad.title) == (FAIL, "Weboberfläche unvollständig oder verändert")
    assert css.name in bad.detail
    # fehlt: ein Chunk, den das Bündel nachlädt
    css.unlink()
    assert ui_check(static, web).level == FAIL
    # ohne Vermerk: Stand unbekannt
    (static / UI_MANIFEST).unlink()
    assert ui_check(static, web).title == "Weboberfläche ohne Build-Vermerk"
    # ohne index.html: fehlt; im Wheel mit dem Hinweis auf pipx
    (static / "index.html").unlink()
    gone = ui_check(static, None, checkout=False)
    assert (gone.level, gone.title) == (FAIL, "Weboberfläche fehlt") and "pipx" in gone.detail


def test_doctor_runs_ui_check(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(doctor, "ui_check", lambda: seen.append(1) or doctor.Check(OK, "Weboberfläche"))
    from ariadne.paths import default_paths

    env = {"HOME": str(tmp_path), "XDG_RUNTIME_DIR": str(tmp_path / "run")}
    checks = doctor.run_checks(default_paths(env))
    assert seen == [1] and any(c.title == "Weboberfläche" for c in checks)


def test_stamp_script_writes_the_same_manifest(tmp_path):
    """``scripts/ui_stamp.py`` schreibt genau den Vermerk, den doctor prüft (hier auf einer Kopie)."""
    static, web = _copy(tmp_path)
    data = doctor.write_ui_manifest(static, web)
    assert data == json.loads((static / UI_MANIFEST).read_text(encoding="utf-8"))
    assert data["files"] == ui_files(static) and data["source_sha256"] == ui_source_hash(web)
    script = (ROOT / "scripts" / "build-ui.sh").read_text(encoding="utf-8")
    assert "npm run build" in script and "scripts/ui_stamp.py" in script and "npm install" not in script
