"""T1 bis T5 (Konzept Fernzugriff 7.1, Vertrag 5): echte HTTP-Anfragen gegen einen echten Server
im Daemon auf einem freien Loopback-Port.

T1 Bindung (R1), T2 Host (R3), T3 Fetch-Metadaten und Origin (R12), T4 Code-Sperre (R5),
T5 Header auf jeder Antwortart (R12). Dazu Peer-UID (R2), Grösse (413) und kaputte Anfragen.
"""

from __future__ import annotations

import os
import pwd
import shutil
import socket
import sys

import pytest

from ariadne.web.config import UiConfigError
from ariadne.web.security import OTHER_CSP, SHELL_CSP
from ariadne.web.server import BindError, bind_socket, check_sockname
from ariadne.web.static import STATIC_DIR
from tests.core.fakeshim import ctl_ok
from tests.web.server.helpers import Web, run_web, use_test_api

pytestmark = pytest.mark.web

ASSET = sorted(p.name for p in (STATIC_DIR / "assets").iterdir() if p.suffix == ".js")[0]
SECURITY_HEADERS = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cache-control": "no-store",
}


@pytest.fixture(autouse=True)
def _api(monkeypatch):
    use_test_api(monkeypatch)


def _ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def _listeners(port: int) -> list[tuple[str, int]]:
    from ariadne.web.peer import parse_proc_net

    out = []
    for name in ("tcp", "tcp6"):
        try:
            with open(f"/proc/net/{name}") as fh:
                text = fh.read()
        except FileNotFoundError:  # ohne IPv6 fehlt tcp6
            continue
        out += [e.local for e in parse_proc_net(text) if e.state == 0x0A and e.local[1] == port]
    return out


# --------------------------------------------------------------------------- #
# T1 Bindung
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "192.168.56.102", "kali.local"])
def test_t1_non_loopback_config_starts_no_server_and_recording_continues(paths, operator, bind):
    async def scenario(web: Web) -> None:
        assert not web.ext.running and web.ext.server is None
        st = await ctl_ok(paths.ctl_sock, "ui.status")
        assert st["running"] is False and st["port"] is None and "Loopback" in st["error"]
        assert (await ctl_ok(paths.ctl_sock, "ping"))["pong"] is True  # Daemon läuft weiter
        res = await web.d.call("ui.code", {})
        assert res["error"]["code"] == "ui_off" and "Loopback" in res["error"]["message"]

    run_web(paths, operator, scenario, config=f'[ui]\nbind = "{bind}"\nport = 0\n')


def test_t1_default_bind_getsockname_and_real_connection(paths, operator):
    async def scenario(web: Web) -> None:
        assert web.ext.running
        name = web.ext.server.sock.getsockname()
        assert name[0] == "127.0.0.1" and name[1] == web.port > 0
        assert _listeners(web.port) == [("127.0.0.1", web.port)]  # nur Loopback, nichts auf 0.0.0.0
        r = await web.req("GET", "/")
        assert r.status_code == 200
        st = await ctl_ok(paths.ctl_sock, "ui.status")
        assert st == {"running": True, "host": "127.0.0.1", "port": web.port, "error": None, "sessions": 0,
                      "inode": web.ext.server.inode, "pid": os.getpid()}

    run_web(paths, operator, scenario)


@pytest.mark.skipif(not _ipv6_loopback(), reason="kein IPv6-Loopback in dieser Umgebung")
def test_t1_ipv6_loopback(paths, operator):
    async def scenario(web: Web) -> None:
        assert web.ext.running
        assert web.ext.server.sock.getsockname()[0] == "::1"
        assert web.ext.ctx.origin == f"http://[::1]:{web.port}"

    run_web(paths, operator, scenario, config='[ui]\nbind = "::1"\nport = 0\n')


def test_t1_port_in_use_and_disabled_fail_closed(paths, operator):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]

    async def busy(web: Web) -> None:
        assert not web.ext.running
        st = await ctl_ok(paths.ctl_sock, "ui.status")
        assert "Port belegt" in st["error"]

    try:
        run_web(paths, operator, busy, config=f"[ui]\nport = {port}\n")
    finally:
        blocker.close()

    async def off(web: Web) -> None:
        st = await ctl_ok(paths.ctl_sock, "ui.status")
        assert st["running"] is False and "abgeschaltet" in st["error"]
        assert (await ctl_ok(paths.ctl_sock, "ui.sessions")) == {"sessions": []}

    run_web(paths, operator, off, config="[ui]\nenabled = false\n")


def test_t1_socket_helpers_refuse_anything_but_loopback():
    for host in ("0.0.0.0", "::", "192.168.56.102", "localhost"):
        with pytest.raises(BindError):
            bind_socket(host, 0)  # wird gar nicht erst gebunden
    with pytest.raises(BindError):
        check_sockname(("0.0.0.0", 7330), "127.0.0.1", 7330)
    with pytest.raises(BindError):
        check_sockname(("127.0.0.1", 7331), "127.0.0.1", 7330)
    assert check_sockname(("127.0.0.1", 40000), "127.0.0.1", 0) == 40000
    assert issubclass(UiConfigError, ValueError)


# --------------------------------------------------------------------------- #
# T2 Host
# --------------------------------------------------------------------------- #


def test_t2_host_header(paths, operator):
    async def scenario(web: Web) -> None:
        p = web.port
        for host in (f"127.0.0.1:{p + 1}", "kali.tail1234.ts.net", "x.trycloudflare.com",
                     f"192.168.56.102:{p}", "127.0.0.1", f"LOCALHOST:{p}", f"127.0.0.1:{p}.evil",
                     f"kali.tail1234.ts.net:{p}", ""):
            for path in ("/", "/api/v1/session"):
                r = await web.req("GET", path, host=host)
                assert r.status_code == 421, (host, path)
                assert r.json()["error"]["code"] == "host"
        for host in (f"127.0.0.1:{p}", f"localhost:{p}", f"[::1]:{p}"):
            assert (await web.req("GET", "/", host=host)).status_code == 200, host
            assert (await web.req("GET", "/api/v1/session", host=host)).status_code == 401, host
        # HTTP/1.0 ohne Host: 421; doppelter Host: 421
        out = await web.raw(b"GET / HTTP/1.0\r\n\r\n")
        assert out.startswith(b"HTTP/1.1 421")
        out = await web.raw(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{p}\r\nHost: 127.0.0.1:{p}\r\n"
                            "Connection: close\r\n\r\n".encode())
        assert out.startswith(b"HTTP/1.1 4")  # h11 (400) oder die Middleware (421)

    run_web(paths, operator, scenario)


# --------------------------------------------------------------------------- #
# T3 Fetch-Metadaten, OPTIONS, Origin
# --------------------------------------------------------------------------- #


def test_t3_fetch_metadata_origin_and_options(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        for site in ("cross-site", "same-site", "irgendwas"):
            for method, path in (("GET", "/"), ("GET", f"/assets/{ASSET}"), ("GET", "/api/v1/test/whoami"),
                                 ("GET", "/karte"), ("POST", "/api/v1/session")):
                r = await web.req(method, path, token=token, headers={"Sec-Fetch-Site": site},
                                  json_body={"code": "x" * 22} if method == "POST" else None)
                assert r.status_code == 403, (site, path)
                assert r.json()["error"]["code"] == "forbidden"
        for site in ("same-origin", "none"):
            r = await web.req("GET", "/api/v1/test/whoami", token=token, headers={"Sec-Fetch-Site": site})
            assert r.status_code == 200
        for origin in ("http://evil.example", "null", None, f"http://localhost:{web.port}",
                       f"https://127.0.0.1:{web.port}"):
            r = await web.req("POST", "/api/v1/test/later", token=token, origin=origin)
            assert r.status_code == 403, origin
            r = await web.req("DELETE", "/api/v1/session", token=token, origin=origin)
            assert r.status_code == 403, origin
        r = await web.req("GET", "/api/v1/test/whoami", token=token, origin="http://evil.example")
        assert r.status_code == 403  # fremder Origin auch beim Lesen
        # Origin muss zum Host passen
        r = await web.req("POST", "/api/v1/test/later", token=token, host=f"localhost:{web.port}",
                          origin=f"http://localhost:{web.port}")
        assert r.status_code == 501
        for path in ("/", "/api/v1/session", "/api/v1/test/whoami"):
            r = await web.req("OPTIONS", path, headers={"Origin": "http://evil.example",
                                                        "Access-Control-Request-Method": "POST"})
            assert r.status_code == 405
            assert not [h for h in r.headers if h.lower().startswith("access-control-")]
        r = await web.req("GET", "/api/v1/test/whoami", token=token)
        assert r.status_code == 200  # das Token gilt noch

    run_web(paths, operator, scenario)


# --------------------------------------------------------------------------- #
# T4 Code-Sperre
# --------------------------------------------------------------------------- #


def test_t4_rejected_requests_never_lock_codes(paths, operator):
    async def scenario(web: Web) -> None:
        code = await web.code()
        for i in range(100):  # abgewiesen an der Middleware: zählen nie als Fehlversuch
            headers = {"Sec-Fetch-Site": "cross-site"} if i % 2 else {}
            r = await web.req("POST", "/api/v1/session", json_body={"code": code}, headers=headers,
                              origin=None if i % 2 == 0 else "http://evil.example")
            assert r.status_code == 403
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})
        assert r.status_code == 200 and len(r.json()["token"]) == 43
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})  # zweimal
        assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"

    run_web(paths, operator, scenario)


def test_t4_five_failures_lock_until_next_code(paths, operator):
    async def scenario(web: Web) -> None:
        valid = await web.code()
        for _ in range(5):
            r = await web.req("POST", "/api/v1/session", json_body={"code": "AAAAAAAAAAAAAAAAAAAAAA"})
            assert r.status_code == 401
        r = await web.req("POST", "/api/v1/session", json_body={"code": valid})
        assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited"
        typed = await web.code(typed=True)  # neuer Code hebt die Sperre auf
        r = await web.req("POST", "/api/v1/session", json_body={"code": valid})
        assert r.status_code == 401  # der alte bleibt ungültig
        r = await web.req("POST", "/api/v1/session", json_body={"code": f"{typed[:5]}-{typed[5:]}".lower()})
        assert r.status_code == 200 and r.json()["session"]["origin"] == "local"
        for bad in ({"code": "kurz"}, {"code": "a" * 65}, {"code": "<script>"}, {"code": 123},
                    {"code": "AAAAAAAAAAAA", "extra": 1}, {}):
            r = await web.req("POST", "/api/v1/session", json_body=bad)
            assert r.status_code == 422, bad
            body = r.json()["error"]
            assert body["code"] == "validation" and "<script>" not in r.text
            assert all(set(d) == {"loc", "type"} for d in body["detail"])
        r = await web.req("POST", "/api/v1/session", content=b"kein json",
                          headers={"Content-Type": "application/json"})
        assert r.status_code == 422

    run_web(paths, operator, scenario)


def test_t4_expired_code_and_local_code_without_readable_process(paths, operator):
    from tests.web.server.test_sessions import FakeClock

    clock = FakeClock()

    async def scenario(web: Web) -> None:
        code = await web.code()
        clock.advance(61)
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})
        assert r.status_code == 401
        code = await web.code()
        web.unreadable()  # Verbindung ohne lesbaren Prozess (wie über den Tunnel)
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})
        assert r.status_code == 401
        web.real_resolver()
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})
        assert r.status_code == 401  # auf dem falschen Weg verbraucht

    run_web(paths, operator, scenario, ext_kw={"clock": clock})


# --------------------------------------------------------------------------- #
# T5 Header
# --------------------------------------------------------------------------- #


def _check_headers(r, *, shell: bool = False) -> None:
    for k, v in SECURITY_HEADERS.items():
        assert r.headers.get(k) == v, (r.request.url, r.status_code, k)
    assert r.headers.get("content-security-policy") == (SHELL_CSP if shell else OTHER_CSP)
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert not [h for h in r.headers if h.lower().startswith("access-control-")]
    assert "server" not in r.headers and "set-cookie" not in r.headers and "x-ariadne-csp" not in r.headers


def test_t5_headers_on_every_kind_of_response(paths, operator):
    async def scenario(web: Web) -> None:
        shell = await web.req("GET", "/")
        assert shell.status_code == 200 and shell.headers["content-type"] == "text/html; charset=utf-8"
        _check_headers(shell, shell=True)
        assert shell.headers["content-security-policy"] == (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        _check_headers(await web.req("GET", "/karte"), shell=True)
        _check_headers(await web.req("HEAD", "/"), shell=True)
        token = await web.login()
        cases = [
            (await web.req("GET", "/api/v1/session", token=token), 200),
            (await web.req("GET", f"/assets/{ASSET}"), 200),
            (await web.req("GET", "/api/v1/session"), 401),
            (await web.req("GET", "/", headers={"Sec-Fetch-Site": "cross-site"}), 403),
            (await web.req("GET", "/api/v1/gibtsnicht", token=token), 404),
            (await web.req("GET", "/assets/gibtsnicht.js"), 404),
            (await web.req("POST", "/", token=token), 405),
            (await web.req("PUT", "/api/v1/session", token=token), 405),
            (await web.req("OPTIONS", "/"), 405),
            (await web.req("GET", "/", host="evil.example"), 421),
            (await web.req("GET", "/api/v1/test/later", token=token), 501),
            (await web.req("GET", "/api/v1/test/boom", token=token), 500),
            (await web.req("POST", "/api/v1/session", json_body={"code": 1}), 422),
        ]
        for r, status in cases:
            assert r.status_code == status, (r.request.url, r.status_code, r.text)
            _check_headers(r)
            if status not in (200,) or r.request.url.path.startswith("/api/"):
                assert r.headers["content-type"] == "application/json; charset=utf-8", r.request.url
        boom = cases[11][0]
        assert boom.json() == {"error": {"code": "internal", "message": "Interner Fehler."}}
        assert "script" not in boom.text
        for _ in range(5):
            await web.req("POST", "/api/v1/session", json_body={"code": "AAAAAAAAAAAAAAAAAAAAAA"})
        r429 = await web.req("POST", "/api/v1/session", json_body={"code": "AAAAAAAAAAAAAAAAAAAAAA"})
        assert r429.status_code == 429
        _check_headers(r429)
        # 413 über Content-Length und über einen Strom ohne Länge
        out = await web.raw(f"POST /api/v1/session HTTP/1.1\r\nHost: 127.0.0.1:{web.port}\r\n"
                            f"Origin: http://127.0.0.1:{web.port}\r\nContent-Length: 2000000\r\n"
                            "Connection: close\r\n\r\n".encode())
        assert out.startswith(b"HTTP/1.1 413") and b"x-frame-options: DENY" in out

        async def big():
            for _ in range(20):
                yield b"x" * 65536

        r413 = await web.req("POST", "/api/v1/test/later", token=token, content=big())
        assert r413.status_code == 413
        _check_headers(r413)
        # kaputte Anfrage: 400 von h11, trotzdem mit Headern
        out = await web.raw(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{web.port}\r\nKaputt\r\n\r\n".encode())
        assert out.startswith(b"HTTP/1.1 400") and b"x-frame-options: DENY" in out
        assert b"frame-ancestors 'none'" in out

    run_web(paths, operator, scenario)


# --------------------------------------------------------------------------- #
# Peer-UID (R2) und Anmeldung
# --------------------------------------------------------------------------- #


def test_api_requires_bearer_and_ignores_token_in_url(paths, operator):
    async def scenario(web: Web) -> None:
        token = await web.login()
        assert (await web.req("GET", "/api/v1/test/whoami", token=token)).json()["origin"] == "local"
        r = await web.req("GET", "/api/v1/test/whoami", headers={"Authorization": "Bearer"})
        assert r.status_code == 401
        for bad in (None, "x", token + "x", token[:-1], "a b"):
            r = await web.req("GET", "/api/v1/test/whoami", token=bad)
            assert r.status_code == 401
        r = await web.req("GET", f"/api/v1/test/whoami?token={token}")
        assert r.status_code == 401  # T8: Token in der URL wird ignoriert
        r = await web.req("GET", "/api/v1/test/whoami", headers={"Authorization": f"Basic {token}"})
        assert r.status_code == 401
        r = await web.req("GET", "/api", token=None)
        assert r.status_code == 401  # Anmeldung vor dem Routing: nichts über Pfade verraten
        assert (await web.req("GET", "/api", token=token)).status_code == 404

    run_web(paths, operator, scenario)


@pytest.mark.skipif(os.getuid() != 0, reason="braucht root, um einen Prozess einer fremden UID zu starten")
def test_r2_connection_of_foreign_uid_is_closed_without_answer(paths, operator):
    try:
        other = next(p for p in pwd.getpwall() if p.pw_uid >= 1000 and p.pw_uid != 65534)
    except StopIteration:
        pytest.skip("kein unprivilegierter Benutzer vorhanden")
    py = shutil.which("python3", path="/usr/bin:/bin") or sys.executable
    script = ("import socket,sys; s=socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=5); "
              "s.sendall(b'GET / HTTP/1.1\\r\\nHost: 127.0.0.1:'+sys.argv[1].encode()+b'\\r\\n\\r\\n'); "
              "d=b''\n"
              "try:\n"
              "    while True:\n"
              "        c=s.recv(65536)\n"
              "        if not c: break\n"
              "        d+=c\n"
              "except OSError: pass\n"
              "print(repr(d))")

    async def scenario(web: Web) -> None:
        import asyncio

        proc = await asyncio.create_subprocess_exec(
            py, "-I", "-c", script, str(web.port), user=other.pw_uid, cwd="/",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), 20)
        assert proc.returncode == 0, err
        assert out.strip() == b"b''"  # keine Antwort, Verbindung zu
        assert (await web.req("GET", "/")).status_code == 200  # der eigene Benutzer kommt durch

    run_web(paths, operator, scenario)


def test_r2_connection_without_entry_is_closed(paths, operator):
    async def scenario(web: Web) -> None:
        web.ext.gate.resolver = lambda client, server: None  # kein Eintrag in /proc/net/tcp
        out = await web.raw(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{web.port}\r\n\r\n".encode())
        assert out == b""
        uid = os.getuid() + 1
        from ariadne.web.peer import PeerInfo

        web.ext.gate.resolver = lambda client, server: PeerInfo(uid=uid, inode=5, pids=(1,))
        assert await web.raw(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{web.port}\r\n\r\n".encode()) == b""
        web.real_resolver()
        assert (await web.req("GET", "/")).status_code == 200

    run_web(paths, operator, scenario)


def test_ui_ops_validate_arguments(paths, operator):
    async def scenario(web: Web) -> None:
        for args in ({"typed": "ja"}, {"via": "mac"}):
            res = await web.d.call("ui.code", args)
            assert res["error"]["code"] == "invalid"
        res = await web.d.call("ui.code", {"via": "sshd"})  # aus dem Daemon selbst: kein sshd-Vorfahre
        assert res["error"]["code"] == "not_sshd"
        res = await ctl_ok(paths.ctl_sock, "ui.code", typed=True)
        assert res["url"] is None and res["display"][5] == "-" and res["expires_in"] == 120
        res = await ctl_ok(paths.ctl_sock, "ui.code")
        assert res["url"] == f"http://127.0.0.1:{web.port}/#c={res['code']}" and res["via"] == "local"
        bad = await web.d.call("ui.revoke", {"session_id": "gibtsnicht"})
        assert bad["error"]["code"] == "not_found"
        assert (await web.d.call("ui.revoke", {"session_id": 5}))["error"]["code"] == "invalid"

    run_web(paths, operator, scenario)



def test_logs_contain_no_paths_queries_codes_or_tokens(paths, operator, caplog):
    import logging

    caplog.set_level(logging.DEBUG)

    async def scenario(web: Web) -> None:
        code = await web.code()
        r = await web.req("POST", "/api/v1/session", json_body={"code": code})
        token = r.json()["token"]
        await web.req("GET", "/api/v1/test/whoami?q=GEHEIM-QUERY", token=token)
        await web.req("GET", "/karte/GEHEIM-PFAD")
        await web.req("GET", f"/api/v1/test/whoami?token={token}")
        await web.req("GET", "/api/v1/test/boom", token=token)
        await web.req("GET", "/", host="GEHEIM-HOST.example")
        # nur die Logs des Servers (der Testclient httpx loggt seine eigenen URLs)
        text = "\n".join(f"{r.name} {r.getMessage()} {r.exc_text or ''}" for r in caplog.records
                         if r.name.startswith(("ariadne", "uvicorn", "fastapi", "starlette")))
        assert "web GET" in text
        for secret in (code, token, "GEHEIM-QUERY", "GEHEIM-PFAD", "GEHEIM-HOST", "<script>", "alert"):
            assert secret not in text, secret
        assert "RuntimeError" in text  # Ausnahmen nur mit ihrer Klasse

    run_web(paths, operator, scenario)


def test_ui_code_waits_for_a_server_that_is_still_starting(paths, operator):
    """``remote serve code`` startet den Daemon und fragt sofort: ``ui.code`` wartet auf den Server,
    statt «aus» zu melden (ctl.sock antwortet schon, bevor die Erweiterungen laufen)."""
    import asyncio

    async def scenario(web: Web) -> None:
        await web.ext.stop()
        res = await web.d.call("ui.code", {})
        assert res["error"]["code"] == "ui_off"
        starting = asyncio.ensure_future(web.ext.start(web.d))
        res = await ctl_ok(paths.ctl_sock, "ui.code")  # gleichzeitig mit dem Start
        await starting
        assert res["port"] == web.ext.server.port and res["url"].endswith(res["code"])
        web.port = web.ext.server.port
        r = await web.req("POST", "/api/v1/session", json_body={"code": res["code"]})
        assert r.status_code == 200

    run_web(paths, operator, scenario)
