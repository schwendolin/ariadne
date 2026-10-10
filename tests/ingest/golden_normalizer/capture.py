"""Nimmt echte Terminal-Bytes für die Normalizer-Goldens auf (manuell ausführen, nicht Teil der Tests).

    python tests/ingest/golden_normalizer/capture.py <fall>

Fälle: ``zsh_highlight`` (zsh mit nachgebauten autosuggestions/syntax-highlighting-
Widgets), ``less_alt``, ``vim_alt``. Die Aufnahme läuft in einem PTY mit 80x24,
isoliertem HOME und ohne Netz. Ergebnis: ``<fall>/input.bin``.
"""

from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

import pexpect

HERE = Path(__file__).parent

ZSHRC = r"""
PS1='%F{green}kali@kali%f:%F{blue}~%f$ '
RPS1=''
setopt promptsp
__mk() { print -rn -- $'\e]133;'"$1"$'\a' }
precmd() { __mk A }
preexec() { __mk C }
# nachgebautes zsh-syntax-highlighting: erstes Wort grün, Rest ohne Farbe
_hl() {
  region_highlight=()
  local w=${BUFFER%% *}
  [[ -n $w ]] && region_highlight+=("0 ${#w} fg=green,bold")
}
# nachgebautes zsh-autosuggestions: Vorschlag aus der "History" in grau
_sugg() {
  local s='nmap -sV -oA scans/lame 10.10.10.3'
  if [[ -n $BUFFER && $s == $BUFFER* && $s != $BUFFER ]]; then
    POSTDISPLAY=${s#$BUFFER}
    region_highlight+=("${#BUFFER} $(( ${#BUFFER} + ${#POSTDISPLAY} )) fg=8")
  else
    POSTDISPLAY=
  fi
}
zle-line-pre-redraw() { _hl; _sugg }
zle -N zle-line-pre-redraw
"""


def _spawn(cmd: list[str], env: dict[str, str]) -> tuple[pexpect.spawn, bytearray]:
    buf = bytearray()

    class Log:
        def write(self, data: bytes) -> None:
            buf.extend(data)

        def flush(self) -> None:
            pass

    child = pexpect.spawn(cmd[0], cmd[1:], env=env, dimensions=(24, 80), encoding=None)
    child.logfile_read = Log()
    return child, buf


def zsh_highlight(home: Path) -> bytes:
    (home / ".zshrc").write_text(ZSHRC)
    env = {"HOME": str(home), "ZDOTDIR": str(home), "TERM": "xterm-256color", "PATH": "/usr/bin:/bin",
           "LANG": "C.UTF-8"}
    child, buf = _spawn(["zsh", "-i"], env)
    child.expect(b"\\$ ")
    for ch in "nmap -sV":
        child.send(ch)
        time.sleep(0.05)
    child.send("\x7f\x7f")  # Backspace
    time.sleep(0.05)
    child.send("sV 10.10.10.3")
    time.sleep(0.1)
    child.send("\x05")  # Ende der Zeile
    time.sleep(0.1)
    child.send("\x03")  # abbrechen, nmap soll nicht laufen
    time.sleep(0.1)
    child.send("print -rn -- 'no newline at end'\r")
    time.sleep(0.2)
    child.send("print -r -- 'Nmap scan report for 10.10.10.3'\r")
    time.sleep(0.2)
    child.send("exit\r")
    child.expect(pexpect.EOF)
    return bytes(buf)


def _pager(home: Path, cmd: list[str], keys: list[str]) -> bytes:
    f = home / "notes.txt"
    f.write_text("".join(f"Zeile {i}: 10.10.10.{i} port {20 + i}/tcp open\n" for i in range(1, 60)))
    env = {"HOME": str(home), "TERM": "xterm-256color", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
           "LESSHISTFILE": "-"}
    child, buf = _spawn([*cmd, str(f)], env)
    time.sleep(0.5)
    for k in keys:
        child.send(k)
        time.sleep(0.2)
    child.expect(pexpect.EOF)
    return bytes(buf)


CASES = {
    "zsh_highlight": zsh_highlight,
    "less_alt": lambda h: _pager(h, ["less"], [" ", "q"]),
    "vim_alt": lambda h: _pager(h, ["vim", "-u", "NONE", "-i", "NONE", "-n"], ["j", "j", ":q!\r"]),
}


def main(name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        data = CASES[name](Path(tmp))
    out = HERE / name
    out.mkdir(exist_ok=True)
    (out / "input.bin").write_bytes(data)
    print(f"{name}: {len(data)} Bytes", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1])
