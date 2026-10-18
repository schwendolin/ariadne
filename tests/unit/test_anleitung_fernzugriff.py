"""Die Anleitung ``docs/anleitung-fernzugriff.md`` gegen den echten Code (Integration v0.1-Server).

Jeder Befehl darin muss so funktionieren, wie er dasteht: ``ariadne …`` nimmt der Parser der CLI
an, ``ariadne-mac …`` kennt der Mac-Helfer, jede Option von ``kali-setup.sh`` steht in seiner
Hilfe, jedes Wort nach ``kali-sl`` kennt ``remote serve``, und die zitierten Meldungen gibt es im
Code wirklich. Platzhalter (``…``, ``SLUG``, ``DATEI``) bleiben stehen, wo der Parser sie als Wert
nimmt; Spannen mit ``…`` als ganzem Argument werden übersprungen.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

import pytest

from ariadne.cli.main import build_parser
from ariadne.remote.serve import ALLOWED

REPO = Path(__file__).resolve().parents[2]
GUIDE = REPO / "docs" / "anleitung-fernzugriff.md"
MAC_HELPER = REPO / "packaging" / "mac" / "ariadne-mac"
KALI_SETUP = REPO / "packaging" / "smartlearn" / "kali-setup.sh"
SRC = REPO / "src" / "ariadne"


def _commands() -> list[str]:
    """Zeilen aus Shell-Blöcken (```bash) und Inline-Code aus dem übrigen Text."""
    out: list[str] = []
    prose: list[str] = []
    fence: str | None = None
    for line in GUIDE.read_text(encoding="utf-8").splitlines():
        if line.startswith("```"):
            fence = line[3:].strip() if fence is None else None
            continue
        if fence is None:
            prose.append(line)
        elif fence in ("bash", "sh") and line.strip() and not line.lstrip().startswith("#"):
            out.append(line.strip())
    out += re.findall(r"`([^`\n]+)`", "\n".join(prose))
    return out


def _words(cmd: str) -> list[str]:
    cmd = re.sub(r"\$\([^)]*\)", "X", cmd)  # $(date …) als ein Wort
    return shlex.split(cmd)


COMMANDS = _commands()


def test_guide_has_the_expected_commands():
    joined = "\n".join(COMMANDS)
    for needle in ("ariadne-mac start", "ariadne-mac stop", "ariadne-mac unlock", "ariadne-mac restore",
                   "sudo sh kali-setup.sh", "ariadne remote check --full", "kali-sl check"):
        assert needle in joined, needle


def _cli_commands() -> list[str]:
    """``ariadne …``-Befehle ohne reine Platzhalter (``ariadne show …``) und ohne Meldungen."""
    out = []
    for c in COMMANDS:
        if re.match(r"ariadne (?!-)", c):
            words = _words(c)
            if "…" not in words and not any(w.endswith(":") for w in words):
                out.append(c)
    return out


@pytest.mark.parametrize("cmd", _cli_commands())
def test_every_ariadne_command_parses(cmd):
    words = _words(cmd)[1:]
    args = build_parser().parse_args(words)
    assert getattr(args, "fn", None) is not None, cmd


def test_every_ariadne_mac_command_is_known():
    main = MAC_HELPER.read_text(encoding="utf-8").split("\nmain() {", 1)[1]
    known = {w for m in re.findall(r"^\s+([a-z|-]+)\)", main, re.M) for w in m.split("|")}
    seen = 0
    for cmd in COMMANDS:
        if not cmd.startswith("ariadne-mac "):
            continue
        words = _words(cmd)
        assert words[1] in known, (cmd, known)
        for opt in words[2:]:
            if opt.startswith("--"):
                assert opt in MAC_HELPER.read_text(), (cmd, opt)
        seen += 1
    assert seen >= 6


def test_every_kali_setup_option_exists():
    help_text = subprocess.run(["sh", str(KALI_SETUP), "--help"], capture_output=True, text=True,
                               check=True).stdout
    seen = 0
    for cmd in COMMANDS:
        if "kali-setup.sh" not in cmd or not cmd.startswith(("sudo sh", "--weg")):
            continue
        for w in _words(cmd):
            if w.startswith("--"):
                assert re.search(rf"^\s+{re.escape(w)}\b", help_text, re.M), (cmd, w)
                seen += 1
    assert seen >= 3


def test_every_word_for_kali_sl_is_allowed_by_remote_serve():
    seen = 0
    for cmd in COMMANDS:
        if not cmd.startswith("ssh ") or "kali-sl" not in cmd:
            continue
        words = _words(cmd)
        rest = words[words.index("kali-sl") + 1:]
        if rest in (["id"], ["…"]):  # Beispiel für «Abgelehnt» bzw. Platzhalter im Text
            continue
        if rest:
            assert rest == [rest[0]] and rest[0] in ALLOWED, cmd
            seen += 1
    assert seen >= 3


# Meldungen, die die Tabelle «Fehlerbilder» und der Text zitieren: so stehen sie im Code.
QUOTED = {
    "Fernzugriff nicht sicher eingerichtet (ariadne remote check)": "remote/serve.py",
    "kein Code von der Kali": "../../packaging/mac/ariadne-mac",
    "Kein Code: ": "remote/serve.py",
    "Web-Oberfläche aus": "web/integration.py",
    "Kein Runtime-Ordner (XDG_RUNTIME_DIR fehlt": "remote/serve.py",
    "Daemon nicht erreichbar": "remote/serve.py",
    "Port $LPORT belegt": "../../packaging/mac/ariadne-mac",
    "Hostkey der Kali unbekannt": "../../packaging/mac/ariadne-mac",
    "Sicherung fehlgeschlagen (": "remote/serve.py",
    "Abgelehnt: In dieser Kali gibt es schon einen Operator-Tresor": "remote/serve.py",
    "Unbekannter Befehl": "remote/serve.py",
    "Abgelehnt: unlock braucht ein Terminal": "remote/serve.py",
    "Fertig: $CHANGED Änderungen.": "../../packaging/smartlearn/kali-setup.sh",
    "Tunnel geschlossen.": "../../packaging/mac/ariadne-mac",
    "liegt in iCloud": "../../packaging/mac/ariadne-mac",
}


@pytest.mark.parametrize("text,where", sorted(QUOTED.items()))
def test_quoted_messages_exist_in_the_code(text, where):
    assert text in (SRC / where).resolve().read_text(encoding="utf-8")


def test_guide_quotes_match_the_table():
    guide = GUIDE.read_text(encoding="utf-8")
    for text in ("Fernzugriff nicht sicher eingerichtet (ariadne remote check)", "kein Code von der Kali",
                 "Kein Runtime-Ordner (XDG_RUNTIME_DIR fehlt", "Daemon nicht erreichbar",
                 "Abgelehnt: unlock braucht ein Terminal", "Fertig: 0 Änderungen."):
        assert text in guide, text


def test_readme_commands_parse():
    """Auch die Kurzanleitung im README: jede ``ariadne …``-Zeile der Shell-Blöcke."""
    text = (REPO / "README.md").read_text(encoding="utf-8")
    seen = 0
    fence: str | None = None
    for line in text.splitlines():
        if line.startswith("```"):
            fence = line[3:].strip() if fence is None else None
            continue
        if fence == "sh" and line.startswith("ariadne "):
            words = _words(line.split("#", 1)[0])[1:]
            assert getattr(build_parser().parse_args(words), "fn", None) is not None, line
            seen += 1
    assert seen >= 10
