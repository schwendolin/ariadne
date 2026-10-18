"""Build-Vermerk der Weboberfläche schreiben und prüfen (aufgerufen von ``scripts/build-ui.sh``).

Schreibt ``src/ariadne/web/static/.build-info.json`` mit dem Hash der webui-Quellen und dem Hash
jeder gebauten Datei und prüft danach mit derselben Funktion wie ``ariadne doctor``, dass
``index.html`` und alle referenzierten Dateien vorhanden sind. Exit 1, wenn nicht.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from ariadne.cli.doctor import OK, ui_check, write_ui_manifest  # noqa: E402


def main() -> int:
    static = ROOT / "src" / "ariadne" / "web" / "static"
    webui = ROOT / "webui"
    if not (static / "index.html").is_file():
        print("Weboberfläche fehlt: zuerst npm run build in webui/", file=sys.stderr)
        return 1
    data = write_ui_manifest(static, webui)
    check = ui_check(static, webui)
    files = data["files"]
    count = len(files) if isinstance(files, dict) else 0
    print(f"Build-Vermerk geschrieben: {count} Dateien, Quellstand {str(data['source_sha256'])[:12]}")
    print(f"Prüfung: {check.title}" + (f" ({check.detail})" if check.detail else ""))
    return 0 if check.level == OK else 1


if __name__ == "__main__":
    raise SystemExit(main())
