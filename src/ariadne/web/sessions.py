"""Einmal-Codes und Sitzungen der Web-Oberfläche (Konzept Fernzugriff R2, R5 bis R7, E92).

Vertrag v0.1-Server 3.4:

* **Codes** entstehen nur im Daemon (ctl ``ui.code``, also nur für denselben Benutzer).
  Lang: 128 Bit base64url, 60 s. Tippcode: 10 Zeichen Crockford-Base32 (50 Bit), 120 s, ohne
  Bindestrich und Gross/klein tolerant. Jeder Code gilt einmal; höchstens 16 offene Codes.
  5 echte Fehlversuche in 60 s machen alle offenen Codes ungültig, bis zum nächsten
  ``ui.code`` antwortet der Tausch mit 429. Ein Code auf dem falschen Weg ist ein Fehlversuch
  und verbraucht den Code.
* **Tokens** haben 256 Bit. Gespeichert wird nur ihr SHA-256 (Vergleich mit
  ``hmac.compare_digest``), nie das Token oder der Code selbst.
* **Bindung** (R2): ``local`` an den lesbaren Prozess hinter der Verbindung beim Tausch,
  ``sshd`` an den sshd-Prozess, der beim Erzeugen des Codes Vorfahre des Aufrufers war. Eine
  Sitzung endet, wenn dieser Prozess endet (PID weg oder andere Startzeit), nach höchstens
  12 h, bei Widerruf und bei den Daemon-Ereignissen (Aufrufer: ``integration.py``).

Die Uhr ist austauschbar (Tests). Abgelaufen ist etwas, wenn die Wanduhr **oder** die Bootzeit
(zählt Suspend mit) die Frist überschreitet; eine angehaltene VM verlängert nichts.
"""

from __future__ import annotations

import collections
import hashlib
import hmac
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from ariadne.web import peer as peer_mod
from ariadne.web.ctx import SessionInfo, SessionOrigin
from ariadne.web.peer import PeerInfo, ProcInfo

__all__ = [
    "AuthError",
    "Clock",
    "SystemClock",
    "SessionStore",
    "CROCKFORD",
    "format_typed",
    "LONG_TTL_S",
    "TYPED_TTL_S",
]

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_IN = {c: c for c in CROCKFORD} | {"O": "0", "I": "1", "L": "1"}
LONG_TTL_S = 60
TYPED_TTL_S = 120
MAX_CODES = 16
MAX_SESSIONS = 32
FAIL_LIMIT = 5
FAIL_WINDOW_S = 60
_NS = 1_000_000_000


class AuthError(Exception):
    """Tausch abgelehnt. ``code`` ist ``unauthorized`` (401) oder ``rate_limited`` (429)."""

    def __init__(self, code: Literal["unauthorized", "rate_limited"]) -> None:
        super().__init__(code)
        self.code = code


class Clock(Protocol):
    def wall_ns(self) -> int: ...

    def boot_ns(self) -> int: ...


class SystemClock:
    """Wanduhr und ``CLOCK_BOOTTIME`` (zählt Suspend mit)."""

    def wall_ns(self) -> int:
        return time.time_ns()

    def boot_ns(self) -> int:
        clk = getattr(time, "CLOCK_BOOTTIME", None)
        return time.clock_gettime_ns(clk) if clk is not None else time.monotonic_ns()


@dataclass(frozen=True)
class _Stamp:
    wall: int
    boot: int


@dataclass
class _Code:
    digest: bytes
    typed: bool
    via: SessionOrigin
    sshd: ProcInfo | None
    stamp: _Stamp
    ttl_ns: int


@dataclass
class _Session:
    info: SessionInfo
    digest: bytes
    proc: ProcInfo
    stamp: _Stamp
    max_age_ns: int
    last_used_ns: int


def _sha(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def format_typed(code: str) -> str:
    """Anzeige eines Tippcodes: ``ABCDE-FGHJK``."""
    return f"{code[:5]}-{code[5:]}" if len(code) == 10 else code


def _normalize_typed(code: str) -> str | None:
    raw = code.replace("-", "").upper()
    if len(raw) != 10:
        return None
    out = []
    for ch in raw:
        mapped = _CROCKFORD_IN.get(ch)
        if mapped is None:
            return None
        out.append(mapped)
    return "".join(out)


def _new_typed() -> str:
    n = secrets.randbits(50)
    return "".join(CROCKFORD[(n >> (5 * i)) & 31] for i in range(9, -1, -1))


class SessionStore:
    """Codes und Sitzungen im Speicher des Daemons (nur Hashes). Nicht thread-sicher: nur im
    Loop des Daemons benutzen."""

    def __init__(
        self,
        *,
        session_hours: int = 12,
        clock: Clock | None = None,
        proc_lookup: Callable[[int], ProcInfo | None] = peer_mod.proc_info,
        alive: Callable[[ProcInfo], bool] = peer_mod.same_process,
        max_codes: int = MAX_CODES,
        max_sessions: int = MAX_SESSIONS,
    ) -> None:
        self.session_hours = max(1, min(12, int(session_hours)))
        self.clock: Clock = clock or SystemClock()
        self._proc_lookup = proc_lookup
        self._alive = alive
        self._max_codes = max_codes
        self._max_sessions = max_sessions
        self._codes: list[_Code] = []
        self._sessions: dict[str, _Session] = {}
        self._fails: collections.deque[int] = collections.deque()
        self.locked_out = False
        self._listeners: list[Callable[[str], None]] = []

    # ------------------------------------------------------------------ #
    # Hilfen
    # ------------------------------------------------------------------ #
    def _stamp(self) -> _Stamp:
        return _Stamp(self.clock.wall_ns(), self.clock.boot_ns())

    def _elapsed(self, stamp: _Stamp) -> int:
        return max(self.clock.wall_ns() - stamp.wall, self.clock.boot_ns() - stamp.boot, 0)

    def _prune_codes(self) -> None:
        self._codes = [c for c in self._codes if self._elapsed(c.stamp) < c.ttl_ns]

    def _fail(self) -> None:
        now = self.clock.boot_ns()
        self._fails.append(now)
        while self._fails and now - self._fails[0] > FAIL_WINDOW_S * _NS:
            self._fails.popleft()
        if len(self._fails) >= FAIL_LIMIT:
            self.locked_out = True
            self._codes.clear()
            self._fails.clear()

    def add_revoke_listener(self, fn: Callable[[str], None]) -> None:
        """``fn(session_id)`` nach jedem Ende einer Sitzung (SSE-Ströme schliessen)."""
        self._listeners.append(fn)

    def _end(self, session_id: str) -> None:
        if self._sessions.pop(session_id, None) is None:
            return
        for fn in list(self._listeners):
            fn(session_id)

    # ------------------------------------------------------------------ #
    # Codes
    # ------------------------------------------------------------------ #
    def issue_code(self, *, typed: bool, via: SessionOrigin, sshd: ProcInfo | None = None) -> tuple[str, int]:
        """Neuer Einmal-Code. Hebt eine Fehlversuchssperre auf. Gibt Code und Gültigkeit (s)."""
        if via not in ("local", "sshd"):
            raise ValueError("via muss local oder sshd sein")
        if via == "sshd" and sshd is None:
            raise ValueError("Code über sshd ohne sshd-Prozess")
        self.locked_out = False
        self._fails.clear()
        self._prune_codes()
        ttl = TYPED_TTL_S if typed else LONG_TTL_S
        code = _new_typed() if typed else secrets.token_urlsafe(16)
        self._codes.append(_Code(_sha(code), typed, via, sshd if via == "sshd" else None, self._stamp(),
                                 ttl * _NS))
        while len(self._codes) > self._max_codes:
            self._codes.pop(0)
        return code, ttl

    def _take_code(self, code: str) -> _Code | None:
        typed_form = _normalize_typed(code)
        long_digest = _sha(code)
        typed_digest = _sha(typed_form) if typed_form is not None else None
        hit: _Code | None = None
        for c in self._codes:
            want = typed_digest if c.typed else long_digest
            # alle vergleichen (konstante Arbeit), den ersten Treffer nehmen
            if want is not None and hmac.compare_digest(c.digest, want) and hit is None:
                hit = c
        if hit is not None:
            self._codes.remove(hit)
        return hit

    @property
    def open_codes(self) -> int:
        self._prune_codes()
        return len(self._codes)

    # ------------------------------------------------------------------ #
    # Tausch und Prüfung
    # ------------------------------------------------------------------ #
    def exchange(self, code: str, peer: PeerInfo) -> tuple[str, SessionInfo]:
        """Code gegen Token (R2, R5). Wirft :class:`AuthError`. Jeder Fehlschlag mit einem
        nicht gesperrten Code zählt als Fehlversuch."""
        if self.locked_out:
            raise AuthError("rate_limited")
        self._prune_codes()
        entry = self._take_code(code)
        if entry is None:
            self._fail()
            raise AuthError("unauthorized")
        proc: ProcInfo | None
        if entry.via == "local":
            # Nur ein lesbarer Prozess der Kali (der Browser); gebunden an genau ihn.
            proc = self._proc_lookup(min(peer.pids)) if peer.pids else None
        else:
            # Über sshd: Verbindung ohne lesbaren Prozess oder der sshd-Prozess selbst.
            proc = entry.sshd
            if proc is not None and peer.pids and proc.pid not in peer.pids:
                proc = None
            if proc is not None and not self._alive(proc):
                proc = None
        if proc is None:
            self._fail()
            raise AuthError("unauthorized")
        token = secrets.token_urlsafe(32)
        stamp = self._stamp()
        max_age = self.session_hours * 3600 * _NS
        sid = secrets.token_hex(4)
        while sid in self._sessions:
            sid = secrets.token_hex(4)
        info = SessionInfo(session_id=sid, origin=entry.via, created_ns=stamp.wall,
                           expires_ns=stamp.wall + max_age, peer_pid=proc.pid, peer_comm=proc.comm[:32])
        self._sessions[sid] = _Session(info, _sha(token), proc, stamp, max_age, stamp.wall)
        while len(self._sessions) > self._max_sessions:
            oldest = min(self._sessions.values(), key=lambda s: s.stamp.boot)
            self._end(oldest.info.session_id)
        return token, info

    def _valid(self, s: _Session) -> bool:
        return self._elapsed(s.stamp) < s.max_age_ns and self._alive(s.proc)

    @staticmethod
    def _peer_ok(s: _Session, peer: PeerInfo) -> bool:
        if s.info.origin == "local":
            return s.proc.pid in peer.pids
        return not peer.pids or s.proc.pid in peer.pids

    def authenticate(self, token: str, peer: PeerInfo) -> SessionInfo | None:
        """Sitzung zum Token, wenn sie gilt und die Verbindung vom gebundenen Prozess kommt."""
        if not token:
            return None
        digest = _sha(token)
        hit: _Session | None = None
        for s in list(self._sessions.values()):
            if hmac.compare_digest(s.digest, digest) and hit is None:
                hit = s
        if hit is None:
            return None
        if not self._valid(hit):
            self._end(hit.info.session_id)
            return None
        if not self._peer_ok(hit, peer):
            return None
        hit.last_used_ns = self.clock.wall_ns()
        return hit.info

    def is_active(self, session_id: str) -> bool:
        s = self._sessions.get(session_id)
        return s is not None and self._valid(s)

    def check(self) -> list[str]:
        """Beendet abgelaufene Sitzungen und solche, deren Prozess endete (Tunnelende, R6)."""
        ended = [sid for sid, s in self._sessions.items() if not self._valid(s)]
        for sid in ended:
            self._end(sid)
        self._prune_codes()
        return ended

    def revoke(self, session_id: str | None = None) -> int:
        """Widerruft eine Sitzung oder (ohne ID) alle; gibt die Zahl zurück."""
        if session_id is None:
            ids = list(self._sessions)
        else:
            ids = [session_id] if session_id in self._sessions else []
        for sid in ids:
            self._end(sid)
        return len(ids)

    def clear(self) -> int:
        """Alles verwerfen: Sitzungen und offene Codes (Sperre, Stopp, Daemon-Ende)."""
        self._codes.clear()
        return self.revoke()

    def __len__(self) -> int:
        return len(self._sessions)

    def listing(self) -> list[dict[str, object]]:
        """Sitzungen für ``ui.sessions`` (nie Token oder Hash)."""
        return [
            {
                "session_id": s.info.session_id,
                "origin": s.info.origin,
                "created_ns": s.info.created_ns,
                "expires_ns": s.info.expires_ns,
                "last_used_ns": s.last_used_ns,
                "peer_pid": s.info.peer_pid,
                "peer_comm": s.info.peer_comm,
            }
            for s in sorted(self._sessions.values(), key=lambda x: x.info.created_ns)
        ]
