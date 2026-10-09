#!/bin/sh
# Ariadne-Launcher (Architektur 3.1). POSIX sh.
#
# Aufruf: launcher.sh <shell-pfad> [shell-args...]
# Liest env.sh aus dem eigenen Verzeichnis (ARIADNE_PYTHON, ARIADNE_PKG_DIR,
# ARIADNE_HOTKEY) und startet den Shim. Fehlt der Interpreter oder das Paket,
# startet die nackte Shell mit ARIADNE_SHIM_FAILED=interpreter.
# Der Launcher darf nie mit einem Fehler enden: sonst schliesst das Terminal.

case $0 in
  */*) __ariadne_dir=${0%/*} ;;
  *) __ariadne_dir=. ;;
esac

# Ein Syntaxfehler in einer per "." gelesenen Datei beendet sh. Darum zuerst
# in einer Subshell prüfen.
if [ -r "$__ariadne_dir/env.sh" ] && (. "$__ariadne_dir/env.sh") >/dev/null 2>&1; then
  . "$__ariadne_dir/env.sh" >/dev/null 2>&1
fi

if [ -n "${ARIADNE_PYTHON:-}" ] && [ -x "$ARIADNE_PYTHON" ] && [ ! -d "$ARIADNE_PYTHON" ] \
  && [ -n "${ARIADNE_PKG_DIR:-}" ] && [ -f "$ARIADNE_PKG_DIR/ariadne/_shim/__main__.py" ] \
  && [ $# -gt 0 ]; then
  export ARIADNE_PYTHON ARIADNE_PKG_DIR
  [ -n "${ARIADNE_HOTKEY:-}" ] && export ARIADNE_HOTKEY
  exec "$ARIADNE_PYTHON" -I -S "$ARIADNE_PKG_DIR/ariadne/_shim/__main__.py" "$@"
fi

ARIADNE_SHIM_FAILED=interpreter
export ARIADNE_SHIM_FAILED
if [ $# -gt 0 ] && [ -x "$1" ] && [ ! -d "$1" ]; then
  exec "$@"
fi
if [ -n "${SHELL:-}" ] && [ -x "$SHELL" ] && [ ! -d "$SHELL" ]; then
  exec "$SHELL" -i
fi
exec /bin/sh -i
