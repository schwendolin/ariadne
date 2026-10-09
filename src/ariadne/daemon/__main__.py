"""``python -m ariadne.daemon``: Daemon im Vordergrund."""

import sys

from ariadne.daemon.main import run_foreground

if __name__ == "__main__":
    sys.exit(run_foreground())
