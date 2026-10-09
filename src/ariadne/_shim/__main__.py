"""Startpunkt des Shims (Architektur 3.1).

Aufruf durch den Launcher::

    python3 -I -S "$ARIADNE_PKG_DIR/ariadne/_shim/__main__.py" <shell> [args...]

Mit ``-I -S`` gibt es weder site-packages noch das Skriptverzeichnis in
``sys.path``. Der Bootstrap hängt ``ARIADNE_PKG_DIR`` (das Verzeichnis, das das
Paket ``ariadne`` enthält) ans Ende von ``sys.path`` und startet den Shim. Jede
Ausnahme vor dem PTY-Start endet in der nackten Shell mit
``ARIADNE_SHIM_FAILED=<grund>``.
"""

import os
import sys


def _fallback(argv: list, reason: str) -> None:
    env = dict(os.environ)
    env["ARIADNE_SHIM_FAILED"] = reason
    shell = env.get("SHELL") or ""
    for cand in (argv, [shell, "-i"], ["/bin/sh", "-i"]):
        if cand and cand[0]:
            try:
                os.execvpe(cand[0], cand, env)  # noqa: S606 - Shell ohne Shim, kein sh -c
            except OSError:
                continue
    os._exit(127)


def main() -> None:
    argv = sys.argv[1:] or [os.environ.get("SHELL") or "/bin/sh", "-i"]
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        pkg = os.environ.get("ARIADNE_PKG_DIR") or os.path.dirname(os.path.dirname(here))
        if pkg not in sys.path:
            sys.path.append(pkg)
        from ariadne._shim.launch import run
    except BaseException:
        _fallback(argv, "import")
        return
    sys.exit(run(argv))


if __name__ == "__main__":
    main()
