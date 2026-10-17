"""E104 in der Auswertung: Echo-Vergleich, Urteil und Anzeige von Eingaben (``ingest/inputs.py``).

Grundsatz: lieber zu viel als zu wenig verdecken. Gespeichert wird immer alles (E26).
"""

from __future__ import annotations

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from ariadne.ingest import inputs as I
from ariadne.store.memory import MemoryJournal

TID = "term-0000-input"


# --------------------------------------------------------------------------- getippt


@pytest.mark.parametrize("data,lines", [
    (b"ls -la\r", ["ls -la"]),
    (b"pasd\x7fs\r", ["pass"]),  # DEL korrigiert
    (b"falsch\x15richtig\r", ["richtig"]),  # Ctrl-U
    (b"cat /etc/x \x17passwd\r", ["cat passwd"]),  # Ctrl-W löscht das letzte Wort
    (b"\x1b[A\r", []),  # Pfeil hoch: nichts Druckbares
    (b"\x1bOA\x03", []),  # SS3-Pfeil, Ctrl-C
    (b"\x1b[200~echo a\necho b\x1b[201~", ["echo a", "echo b"]),  # Paste mit zwei Zeilen
    (b"cd /et\t\r", ["cd /et"]),  # Tab fällt weg
    (b"\r", []),
])
def test_typed_lines(data, lines):
    assert I.typed_lines(data) == lines


# --------------------------------------------------------------------------- Ausgabe


def test_render_handles_cr_bs_and_line_editor_redraws():
    # zsh mit Syntax-Hervorhebung zeichnet die Zeile mit Farben und Cursor-Sprüngen neu
    out = b"$ l\x1b[1D\x1b[31ml\x1b[39ms\x1b[2D\x1b[32mls\x1b[39m\x1b[K\r\n"
    assert I.render_output(out)[0] == "$ ls"
    assert I.render_output(b"abc\b\bX\r\n") == ["aXc", ""]
    assert I.render_output(b"12345\rab\x1b[K") == ["ab"]
    assert I.render_output(b"x\x1b]0;Titel\x07y") == ["xy"]


# --------------------------------------------------------------------------- Echo-Vergleich


def test_remote_shell_echo_is_seen():
    assert I.echo_seen(b"id\r", b"id\r\n") is True
    assert I.echo_seen(b"cd /etc/passwd-\t\r", b"cd /etc/passwd-old \r\n") is True  # lang: irgendwo
    assert I.echo_seen(b"cat x\r", b"cat y\r\n") is False


def test_tab_completion_is_a_placeholder():
    """Was die Shell beim Tab ergänzt, kennt nur die Ausgabe."""
    assert I.echo_seen(b"cd /et\t\r", b"cd /etc/\r\n") is True
    assert I.echo_seen(b"cat /et\tpas\t\r", b"cat /etc/passwd\r\n") is True
    assert I.echo_seen(b"ls Dok\t\x7f\r", b"ls Dokumente\r\n") is True  # Backspace nach dem Tab
    assert I.echo_seen(b"cd /et\t\r", b"cd /usr/\r\n") is False
    # echte zsh (compinit): «ls Dok», Tab, Enter
    zsh = b"l\x08ls Dokumente\x1b[1m/\x1b[0m\x08\x1b[0m \x08\x1b[?2004l\r\r\n"
    assert I.echo_seen(b"ls Dok\t\r", zsh) is True
    assert I.echo_seen(b"a\tb\tc\td\te\tf\r", b"a1b2c3d4e5f\r\n") is False  # zu viele Platzhalter


def test_right_prompt_and_suggestions_right_of_the_cursor():
    """zsh mit RPROMPT (Kali zeigt nach einem Fehler ``1 ⨯`` rechts): Die Zeile endet nicht mit
    dem Getippten, aber der Cursor stand beim Enter direkt dahinter. Aufgenommen aus echter zsh."""
    out = b"# \x1b[K\x1b[74C[1]\x1b[77Dl\x08ls\x1b[?2004l\r\r\nexp.py\r\n"
    assert I.render_output(out)[0].endswith("[1]")
    assert I.echo_seen(b"ls\r", out) is True
    # zsh-autosuggestions: Vorschlag rechts vom Cursor, beim Enter nicht gelöscht
    sug = b"$ i\x1b[90md -u\x1b[0m\x1b[4Dd\x1b[?2004l\r\r\n"
    assert I.render_output(sug)[0] == "$ id -u"
    assert I.echo_seen(b"id\r", sug) is True


def test_placeholder_is_one_word_and_anchored():
    assert I.echo_seen(b"cat\tx\r", b"cat foo x\r\n") is False  # Ergänzung ohne Leerzeichen
    assert I.echo_seen(b"ls Dok\t\r", b"ls Dokumente/ \r\n") is True  # zsh hängt ein Leerzeichen an
    assert I.echo_seen(b"toor\t\r", b"toor@lame's password: \r\n") is False  # vorab getippt
    assert I.echo_seen(b"cd /etc/passwd-\t -la\r", b"x cd /etc/passwd-old -la y\r\n") is True  # lang


@settings(max_examples=200, deadline=None)
@given(pw=st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), min_size=1, max_size=40),
       prompt=st.text(alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E), max_size=60))
def test_password_absent_from_output_is_never_seen(pw, prompt):
    """Sicherheit: Steht das Getippte nirgends in der Ausgabe, gilt es nie als Echo."""
    assume(pw not in prompt)
    assert I.echo_seen(pw.encode() + b"\r", prompt.encode() + b"\r\r\n") is False
    assert I.classify(pw.encode() + b"\r", tty_no_echo=False, output=prompt.encode() + b"\r\n").hidden


def test_hostile_long_line_is_fast():
    """Die Ausgabe kommt vom Ziel: Der Vergleich ist linear (kein Rückverfolgen wie bei Regex)."""
    import time

    line = b"a" * 200_000 + b"\r\n"
    t0 = time.monotonic()
    assert I.echo_seen(b"a\ta\ta\ta\tb\r", line) is False
    assert I.echo_seen(b"aaaaaaaaaaaaaaaaab\r", line) is False
    assert time.monotonic() - t0 < 1.0


def test_password_without_echo_is_not_seen():
    assert I.echo_seen(b"hunter2\r", b"\r\n") is False
    assert I.echo_seen(b"hunter2\r", b"*******\r\n") is False  # Sternchen sind kein Echo
    assert I.echo_seen(b"\r", b"\r\n") is None


def test_short_secret_typed_ahead_into_prompt_is_not_an_echo():
    """Vorab getippt, dann erscheint der Prompt: «root» steht darin, beendet aber keine Zeile,
    und der Cursor steht beim Enter hinter dem Prompt, nicht hinter «root»."""
    assert I.echo_seen(b"root\r", b"root@10.10.10.3's password: \r\n") is False
    assert I.echo_seen(b"root\t\r", b"root@10.10.10.3's password: \r\n") is False
    assert I.echo_seen(b"msfadmin\r", b"[sudo] password for msfadmin: \r\r\n") is False


def test_output_window_cuts_after_enter_and_detects_gaps():
    chunks = [(100, b"pw"), (102, b": "), (104, b"\r\nWelcome to lame\r\n")]
    assert I.output_window(chunks, 102, 104, b"x\r") == b": \r\n"
    assert I.output_window([(100, b"ab"), (110, b"cd")], 100, 105, b"x\r") is None  # Lücke
    assert I.output_window([], 50, 50, b"x\r") == b""  # nichts danach (noch nicht gespeichert)
    # Paste in einem Stück: das Echo kommt erst danach
    assert I.output_window([(0, b"whoami\r\nroot\r\n")], 0, 0, b"\x1b[200~whoami\x1b[201~") == b"whoami\r\n"


# --------------------------------------------------------------------------- Urteil, Anzeige


def test_classify_prefers_hiding():
    assert I.classify(b"hunter2\r", tty_no_echo=True, output=b"hunter2\r\n").reason == "tty_no_echo"
    assert I.classify(b"id\r", tty_no_echo=False, output=None).reason == "no_output"
    assert I.classify(b"hunter2\r", tty_no_echo=False, output=b"\r\n").reason == "no_echo_seen"
    v = I.classify(b"id\r", tty_no_echo=False, output=b"id\r\n")
    assert (v.hidden, v.reason, v.printable) == (False, None, 2)
    assert I.classify(b"\x03", tty_no_echo=True, output=None).hidden is False  # nichts zu verdecken


def test_display_text_masks_and_shows_control_chars():
    hidden = I.InputVerdict(True, "tty_no_echo", 7)
    assert I.display_text(b"hunter2\r", hidden) == I.MASK
    assert I.display_text(b"hunter2\r", hidden, reveal=True) == "hunter2"
    shown = I.InputVerdict(False, None, 3)
    assert I.display_text(b"a\x1b]0;x\x07b\r", shown) == "a<ESC>]0;x<BEL>b"
    assert I.display_text(b"x" * 5000, shown).endswith("…")


# --------------------------------------------------------------------------- Journal


def _journal() -> MemoryJournal:
    """Strom wie im Terminal: Echo einer lokalen Shell, sudo (Passwortmodus), Remote-Passwort."""
    j = MemoryJournal()
    pos = 0

    def out(data: bytes) -> None:
        nonlocal pos
        j.append("term.out", {"terminal_id": TID, "stream_off": pos, "length": len(data), "t_shim_ns": 1},
                 data, terminal_id=TID, stream_off=pos)
        pos += len(data)

    def typed(data: bytes, echo: bytes, after: bytes, *, flag: bool = False) -> None:
        start = pos
        if echo:
            out(echo)
        h = {"terminal_id": TID, "stream_off": start, "out_end": pos, "length": len(data), "t_shim_ns": 5}
        if flag:
            h["no_echo"] = True
        out(after)
        j.append("term.input", h, data, terminal_id=TID, stream_off=start)

    out(b"$ ")
    typed(b"id\r", b"id", b"\r\nuid=0(root)\r\n$ ")
    typed(b"sudo -v\r", b"sudo -v", b"\r\n[sudo] Passwort: ")
    typed(b"Geheim-4711\r", b"", b"\r\n$ ", flag=True)
    out(b"Password: ")
    typed(b"remote-pw\r", b"", b"\r\n")
    return j


def test_collect_inputs_hides_password_prompts_and_never_reveals():
    j = _journal()
    items = I.collect_inputs(j)
    assert [(x["hidden"], x["reason"], x["text"]) for x in items] == [
        (False, None, "id"),
        (False, None, "sudo -v"),
        (True, "tty_no_echo", I.MASK),
        (True, "no_echo_seen", I.MASK),
    ]
    assert all(x["revealed"] is False for x in items)
    assert "Geheim" not in repr(items) and "remote-pw" not in repr(items)
    assert [x["text"] for x in I.collect_inputs(j, limit=1)] == [I.MASK]


def test_input_by_seq_reveals_only_on_request():
    j = _journal()
    seq = I.collect_inputs(j)[2]["seq"]
    assert I.input_by_seq(j, seq)["text"] == I.MASK
    item = I.input_by_seq(j, seq, reveal=True)
    assert item["text"] == "Geheim-4711" and item["revealed"] is True
    assert I.input_by_seq(j, 1) is None  # kein term.input
