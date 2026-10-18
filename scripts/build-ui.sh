#!/usr/bin/env bash
# Baut die Weboberfläche (webui/) nach src/ariadne/web/static und schreibt den Build-Vermerk
# (.build-info.json: Hash der webui-Quellen und jeder gebauten Datei). Der Build ist eingecheckt,
# damit eine Installation aus dem Git-Repo (pipx, Wheel) die Oberfläche enthält.
#
# Aufruf aus dem Checkout:  scripts/build-ui.sh
# Danach prüfen:            ariadne doctor   (Zeile «Weboberfläche»)
#
# Braucht Node 22 (npm) und die Python-Umgebung des Checkouts (.venv oder $PYTHON).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
py="${PYTHON:-}"
if [ -z "$py" ]; then
  if [ -x "$root/.venv/bin/python" ]; then py="$root/.venv/bin/python"; else py="python3"; fi
fi

cd "$root/webui"
if [ ! -d node_modules ]; then
  echo "webui: node_modules fehlt, installiere exakt nach package-lock.json (npm ci)"
  npm ci --no-audit --no-fund
fi
npm run build
cd "$root"
"$py" "$root/scripts/ui_stamp.py"
