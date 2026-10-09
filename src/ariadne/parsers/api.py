"""Parser-Schnittstelle (Architektur 5.6).

Parser sind deterministisch und isoliert testbar:

* Sie greifen nie auf die Datenbank zu und lösen keine Identitäten auf.
* Sie bekommen eine nur lesbare :class:`UnitView` und liefern :class:`Obs`
  (Beobachtungen) und :class:`Mention` (erkannte Werte ohne Kartenwirkung).
* XML nur über :func:`ariadne.parsers.safe.safe_xml_parse`, Regex nur über
  ``re2`` (``ariadne.parsers.safe.re2``). Ein Import-Hook in den Tests
  verbietet ``xml.etree``, ``xml.dom`` und ``lxml`` in Parser-Modulen.
* Sie laufen später in Worker-Prozessen ohne Schlüssel. Deshalb müssen alle
  Ein- und Ausgaben serialisierbar sein (:meth:`Obs.to_dict`).
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal, Protocol, runtime_checkable

__all__ = [
    "Trust",
    "UnitKind",
    "Span",
    "Ref",
    "Obs",
    "Mention",
    "Line",
    "SgrSpan",
    "UnitView",
    "Parser",
    "BASE_CONFIDENCE",
]

Trust = Literal["user", "structured", "tool_text", "heuristic", "ai", "ocr"]
UnitKind = Literal["command", "segment", "file", "image"]

BASE_CONFIDENCE: Mapping[Trust, float] = {
    "user": 1.0,
    "structured": 0.95,
    "tool_text": 0.85,
    "ai": 0.5,
    "ocr": 0.5,
    "heuristic": 0.4,
}


@dataclass(frozen=True)
class Span:
    """Fundstelle in der Einheit. Zeilen sind 0-basiert, ``line_end`` inklusiv."""

    line_start: int
    line_end: int
    col_start: int | None = None
    col_end: int | None = None
    path: str | None = None  # XPath oder JSONPath bei strukturierten Dateien

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass(frozen=True)
class Ref:
    """Verweis auf ein Subjekt über eine Kennung, nie über eine Entitäts-ID.

    Kennungen (Architektur 5.8) haben die Form ``<typ>:<wert>``:

    * ``ip:<adressraum>/<adresse>``    z. B. ``ip:default/10.10.10.5``
    * ``mac:<aa:bb:..>``, ``fqdn:<name>``, ``netbios:<NAME>``
    * ``sshkey:<typ>:<sha256-fingerprint>``, ``sid:<S-1-5-...>``
    * ``ctx:host``                     Host der aktuellen Kontextspanne
    * ``svc:<host-kennung>|<proto>/<port>``
    * ``url:<normalisierte URL>``
    * ``id:<realm>|<name>``            Identität, Realm ``ad:<domain>``,
                                         ``local:<host-kennung>`` oder ``app:<svc>``
    * ``secret:<art>|<wert>``          Klartext nur hier; die Projektion ersetzt
                                         den Wert durch ein HMAC (chain.secret_key)
    """

    key: str

    # ---- Konstruktoren ---------------------------------------------------- #
    @staticmethod
    def ip(addr: str, space: str = "default") -> Ref:
        return Ref(f"ip:{space}/{addr}")

    @staticmethod
    def mac(addr: str) -> Ref:
        return Ref(f"mac:{addr.lower()}")

    @staticmethod
    def fqdn(name: str) -> Ref:
        return Ref(f"fqdn:{name.lower().rstrip('.')}")

    @staticmethod
    def netbios(name: str) -> Ref:
        return Ref(f"netbios:{name.upper()}")

    @staticmethod
    def sshkey(keytype: str, fingerprint: str) -> Ref:
        return Ref(f"sshkey:{keytype}:{fingerprint}")

    @staticmethod
    def ctx_host() -> Ref:
        return Ref("ctx:host")

    @staticmethod
    def service(host: Ref, proto: str, port: int) -> Ref:
        return Ref(f"svc:{host.key}|{proto.lower()}/{int(port)}")

    @staticmethod
    def url(url: str) -> Ref:
        return Ref(f"url:{url}")

    @staticmethod
    def identity(realm: str, name: str) -> Ref:
        return Ref(f"id:{realm}|{name}")

    @staticmethod
    def secret(kind: str, value: str) -> Ref:
        return Ref(f"secret:{kind}|{value}")

    @property
    def type(self) -> str:
        return self.key.split(":", 1)[0]

    def __str__(self) -> str:  # pragma: no cover - Anzeige
        return self.key


@dataclass(frozen=True)
class Obs:
    """Beobachtung: Subjekt, Prädikat aus der Ontologie, Wert, Fundstelle."""

    subject: Ref
    predicate: str
    value: str | int | bool | Ref
    span: Span
    confidence: float | None = None  # None = Basiswert der Vertrauensklasse
    attrs: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        v = self.value
        return {
            "subject": self.subject.key,
            "predicate": self.predicate,
            "value": {"ref": v.key} if isinstance(v, Ref) else v,
            "span": self.span.to_dict(),
            "confidence": self.confidence,
            "attrs": dict(self.attrs),
        }


@dataclass(frozen=True)
class Mention:
    """Erkannter Wert ohne Wirkung auf Karte oder Inbox (durchsuchbar)."""

    value_type: str  # ip, cidr, url, email, cve, hash, jwt, privkey, awskey, ...
    value: str
    span: Span
    attrs: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "value_type": self.value_type,
            "value": self.value,
            "span": self.span.to_dict(),
            "attrs": dict(self.attrs),
        }


@dataclass(frozen=True)
class SgrSpan:
    """Farb-/Attributspanne innerhalb einer normalisierten Zeile."""

    col_start: int
    col_end: int
    fg: str | None = None  # z. B. "red", "yellow", "bright_red", "#rrggbb"
    bg: str | None = None
    bold: bool = False
    concealed: bool = False


@dataclass(frozen=True)
class Line:
    """Normalisierte Zeile mit Rückbezug auf den Rohstrom (Architektur 5.5)."""

    text: str
    raw_start: int  # absoluter Stream-Offset bzw. Byte-Offset in der Datei
    raw_end: int
    sgr: tuple[SgrSpan, ...] = ()
    prompt_echo: bool = False  # Bereich A..C: nie an Parser
    concealed: bool = False  # enthält verdeckten Text
    overwritten: bool = False  # Text wurde vor dem Zeilenende überschrieben


@runtime_checkable
class UnitView(Protocol):
    """Nur lesbare Sicht auf eine Einheit.

    ``lines`` enthält bei Befehlen und Segmenten keine ``prompt_echo``-Zeilen.
    """

    unit_id: str
    kind: UnitKind
    argv: Sequence[str]  # leer bei Dateien und Bildern
    cmd_text: str | None
    exit_code: int | None
    cwd: str | None
    context: Mapping[str, Any]  # Stage-Dict der Kontextspanne (kind, host, user)
    lines: Sequence[Line]
    path: str | None  # bei Dateien: Pfad relativ zum Arbeitsbereich
    mime: str | None
    sniff: str | None
    ts_utc_ns: int

    def open_bytes(self) -> bytes: ...


@runtime_checkable
class Parser(Protocol):
    id: ClassVar[str]  # z. B. "nmap.xml"
    version: ClassVar[str]  # Änderung -> Reparse-Angebot
    trust: ClassVar[Trust]
    auto_eligible: ClassVar[bool]  # darf der Automodus direkt übernehmen?

    def match(self, unit: UnitView) -> int:
        """0 = nicht zuständig, sonst Priorität (höher gewinnt). Muss billig sein."""
        ...

    def parse(self, unit: UnitView) -> Iterator[Obs | Mention]: ...

    def companions(self, argv: Sequence[str], cwd: str) -> list[str]:
        """Dateien, die dieser Befehl schreibt (z. B. ``-oX``), absolut oder relativ zu cwd."""
        ...


ParserFactory = Callable[[], Parser]
