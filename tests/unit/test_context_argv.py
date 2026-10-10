"""``ctxrules.context_argv``: Shell-Upgrade ``stty raw -echo; fg`` holt die Remote-Stufe zurück."""

from __future__ import annotations

from ariadne.ctxrules import ContextStack, command_argvs, context_argv


def test_command_argvs():
    assert command_argvs("stty raw -echo; fg") == [["stty", "raw", "-echo"], ["fg"]]
    assert command_argvs("nmap -oN out.txt x > log; echo ok") == [
        ["nmap", "-oN", "out.txt", "x"], ["echo", "ok"]]
    assert command_argvs("") == []


def test_context_argv():
    assert context_argv("stty raw -echo; fg") == ["fg"]
    assert context_argv("stty raw -echo && fg %1") == ["fg", "%1"]
    assert context_argv("nc -lvnp 4444 | tee log") == ["nc", "-lvnp", "4444"]
    assert context_argv("echo a; ssh root@x") == ["echo", "a"]  # nur fg/%n wird nachgezogen


def test_upgrade_resumes_suspended_stage():
    st = ContextStack()
    st.on_command_start(context_argv("nc -lvnp 4444"), 10)
    assert not st.is_local()
    st.on_command_end(148, 50)  # Ctrl-Z
    assert st.is_local()
    st.on_command_start(context_argv("stty raw -echo; fg"), 60)
    assert not st.is_local() and st.top().kind == "revshell"
