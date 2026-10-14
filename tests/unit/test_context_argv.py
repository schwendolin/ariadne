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


def test_fg_resumes_the_job_the_shell_resumes():
    """Befund: fg holte immer die jüngste angehaltene Stufe, auch wenn die Shell vim fortsetzt."""
    st = ContextStack()
    st.on_command_start(context_argv("nc -lvnp 4444"), 100)
    st.on_command_end(148, 500)  # nc angehalten (Job 1)
    st.on_command_start(context_argv("vim notes.txt"), 600)
    st.on_command_end(148, 700)  # vim angehalten (Job 2, ohne Stufe)
    st.on_command_start(context_argv("fg"), 800)
    assert st.is_local()  # vim ist zurück, nicht die Reverse Shell
    st.on_command_end(0, 900)  # vim beendet
    assert [s.state for s in st.stages[1:]] == ["suspended"]
    st.on_command_start(context_argv("fg"), 1000)
    assert st.top().kind == "revshell"


def test_fg_with_job_number_and_unclear_jobs():
    st = ContextStack()
    st.on_command_start(context_argv("ssh root@10.10.10.5"), 10)
    st.on_command_end(148, 20)  # %1 ssh
    st.on_command_start(context_argv("less log"), 30)
    st.on_command_end(148, 40)  # %2 less
    st.on_command_start(context_argv("fg %1"), 50)
    assert st.top().kind == "ssh"
    st.on_command_end(148, 60)  # ssh wieder angehalten: jüngster Job
    st.on_command_start(context_argv("%nc"), 70)  # Name: unklar, nichts aktivieren
    assert st.is_local()
    st.on_command_start(context_argv("fg %7"), 80)  # gibt es nicht
    assert st.is_local()
    st.on_command_start(context_argv("fg %-"), 90)  # vorletzter Job: less
    assert st.is_local()
    st.on_command_start(context_argv("fg"), 95)
    assert st.top().kind == "ssh"
    # nach einem Schnappschuss ist die Reihenfolge unbekannt: jüngste angehaltene Stufe
    snap = ContextStack.from_snapshot([{"kind": "local", "host": "local"},
                                       {"kind": "revshell", "opened_at": 5, "state": "suspended"}])
    assert snap.jobs is None
    snap.on_command_start(context_argv("fg"), 100)
    assert snap.top().kind == "revshell"
