"""``ariadne ai check``: Prüfliste für das KI-Gateway (ok, warn, fail).

* Einstellungen gültig, Anbieter und Modell gesetzt.
* Cloud: API erreichbar über eine direkte Verbindung (ohne Proxy der Umgebung) und TLS ohne Aufbruch:
  Die Kette muss gegen die Mozilla-Liste (``certifi``) gültig sein; genau diese Liste nutzt auch der
  Anbieter ``cloud`` (:func:`ariadne.ai.providers.mozilla_tls_context`, nie den Speicher des Systems).
  Gilt sie nur mit dem Zertifikatsspeicher des Systems, endet sie in einer lokal hinzugefügten CA (Burp,
  Firmen-Proxy): ``fail``; der echte Aufruf scheitert dann ebenfalls (Fehler ``tls``). Ein gesetzter
  Proxy in der Umgebung ist ``warn`` (Ariadne nutzt ihn nicht).
* Lokal: Ollama antwortet auf ``127.0.0.1``.

Die Prüfung sendet keine Secrets und keine Projektdaten; nur ein TLS-Handshake und ``HEAD /``.
"""

from __future__ import annotations

import socket
import ssl
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal

from ariadne.ai.config import AiConfig
from ariadne.ai.providers import API_HOST, LocalProvider

__all__ = ["Check", "Probe", "tls_probe", "run_checks", "worst", "PROXY_VARS"]

Level = Literal["ok", "warn", "fail"]
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


@dataclass(frozen=True)
class Check:
    level: Level
    name: str
    text: str


@dataclass(frozen=True)
class Probe:
    """Ergebnis eines TLS-Versuchs: ``reachable`` (TCP), ``verified`` (Kette gültig), ``http_status``."""

    reachable: bool
    verified: bool
    http_status: int | None = None


def _mozilla_cafile() -> str | None:
    try:
        import certifi

        return str(certifi.where())
    except ImportError:
        return None


def tls_probe(host: str, port: int, cafile: str | None, timeout: float = 10.0) -> Probe:
    """Direkte Verbindung (kein Proxy), TLS mit Prüfung gegen ``cafile`` (``None``: Systemspeicher)."""
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        raw = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return Probe(False, False)
    try:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode("ascii"))
            line = tls.recv(64).split(b"\r\n", 1)[0]
            parts = line.split()
            status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else None
            return Probe(True, True, status)
    except ssl.SSLCertVerificationError:
        return Probe(True, False)
    except (OSError, ssl.SSLError):
        return Probe(True, False)
    finally:
        raw.close()


ProbeFn = Callable[[str, int, "str | None"], Probe]


def _default_probe(host: str, port: int, cafile: str | None) -> Probe:
    return tls_probe(host, port, cafile)


def run_checks(
    cfg: AiConfig | None,
    *,
    key_present: bool | None,
    env: Mapping[str, str],
    probe: ProbeFn | None = None,
    ollama_ping: Callable[[], bool] | None = None,
) -> list[Check]:
    probe = probe or _default_probe
    out: list[Check] = []
    if cfg is None:
        return [Check("fail", "Einstellungen", "ai.toml ungültig: ariadne ai setup")]
    if cfg.provider == "off":
        return [Check("warn", "Anbieter", "KI ist aus (Standard): ariadne ai setup")]
    out.append(
        Check(
            "ok" if cfg.model else "fail",
            "Modell",
            "Modell-ID gesetzt" if cfg.model else "keine Modell-ID: ariadne ai setup --model <ID>",
        )
    )
    if cfg.provider == "local":
        ping = ollama_ping or LocalProvider(cfg.model or "-", port=cfg.local_port).ping
        ok = ping()
        out.append(
            Check(
                "ok" if ok else "fail",
                "Ollama",
                f"Ollama antwortet auf 127.0.0.1:{cfg.local_port}"
                if ok
                else f"Ollama auf 127.0.0.1:{cfg.local_port} nicht erreichbar (ollama serve?)",
            )
        )
        return out
    if key_present is None:
        out.append(Check("warn", "API-Key", "Daemon nicht erreichbar oder gesperrt: Schlüssel nicht geprüft"))
    else:
        out.append(
            Check(
                "ok" if key_present else "fail",
                "API-Key",
                "API-Key im Operator-Tresor" if key_present else "kein API-Key: ariadne ai setup",
            )
        )
    proxies = [v for v in PROXY_VARS if env.get(v)]
    if proxies:
        out.append(
            Check(
                "warn", "Proxy", "Proxy in der Umgebung gesetzt; Ariadne verbindet direkt und nutzt ihn nicht"
            )
        )
    else:
        out.append(Check("ok", "Proxy", "kein Proxy in der Umgebung"))
    moz = _mozilla_cafile()
    p_moz = probe(API_HOST, 443, moz) if moz else None
    if p_moz is not None and not p_moz.reachable:
        out.append(Check("fail", "Erreichbar", f"{API_HOST}:443 nicht erreichbar (Netz, DNS oder Filter)"))
        return out
    if p_moz is not None and p_moz.verified:
        out.append(
            Check(
                "ok",
                "Erreichbar",
                f"{API_HOST} antwortet" + (f" (HTTP {p_moz.http_status})" if p_moz.http_status else ""),
            )
        )
        out.append(
            Check("ok", "TLS", "Zertifikatskette gültig gegen die Mozilla-Liste, kein Aufbruch erkannt")
        )
        return out
    p_sys = probe(API_HOST, 443, None)
    if not p_sys.reachable:
        out.append(Check("fail", "Erreichbar", f"{API_HOST}:443 nicht erreichbar"))
        return out
    if p_moz is None:
        out.append(
            Check(
                "warn",
                "TLS",
                "Mozilla-Liste (certifi) fehlt: Aufbruch nicht prüfbar"
                if p_sys.verified
                else "Zertifikatskette ungültig",
            )
        )
        return out
    if p_sys.verified:
        out.append(
            Check("fail", "TLS", "Kette nur mit lokal hinzugefügter CA gültig: TLS-Aufbruch (Proxy, Burp)")
        )
    else:
        out.append(Check("fail", "TLS", "Zertifikatskette ungültig: fremde CA oder Aufbruch"))
    return out


def worst(checks: list[Check]) -> Level:
    levels = {c.level for c in checks}
    return "fail" if "fail" in levels else "warn" if "warn" in levels else "ok"
