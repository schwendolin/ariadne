"""Sichere Bausteine für Parser (Architektur 5.6, 9.2).

* XML nur über :func:`safe_xml_parse` bzw. :func:`safe_xml_iterparse`
  (defusedxml mit ``forbid_dtd``, ``forbid_entities``, ``forbid_external``).
  Eine leere Dokumenttyp-Deklaration ``<!DOCTYPE name>`` (so beginnt jede
  nmap-XML-Datei) deklariert nichts und wird vorher durch Leerzeichen gleicher
  Länge ersetzt. Jede andere DTD (internes Subset, ``SYSTEM``, ``PUBLIC``)
  bleibt stehen und lässt defusedxml abbrechen: :class:`UnsafeXmlError`.
* Regex nur über ``re2`` (lineare Laufzeit, keine Rückverweise). :func:`rx`
  kompiliert mit Cache, :func:`clip` kürzt Zeilen über 16 KiB vor dem Scannen.
"""

from __future__ import annotations

import io
from collections.abc import Iterator, Sequence
from functools import lru_cache
from typing import Any

import defusedxml.ElementTree as _det
import re2
from defusedxml import DefusedXmlException

__all__ = [
    "MAX_LINE",
    "MAX_XML_BYTES",
    "ParseError",
    "UnsafeXmlError",
    "neutralize_doctype",
    "safe_xml_parse",
    "safe_xml_iterparse",
    "rx",
    "clip",
    "decode",
]

MAX_LINE = 16 * 1024
MAX_XML_BYTES = 64 << 20

ParseError = _det.ParseError

_OPTS = re2.Options()
_OPTS.log_errors = False


class UnsafeXmlError(ValueError):
    """XML mit DTD, Entities oder externen Verweisen oder über der Grösse: nie auswerten."""


_NAME_CHARS = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.:")
_WS = frozenset(b" \t\r\n")


def neutralize_doctype(data: bytes) -> bytes:
    """Ersetzt eine leere ``<!DOCTYPE name>``-Deklaration im Prolog durch Leerzeichen.

    Zeilenumbrüche und Längen bleiben erhalten. Alles andere bleibt unverändert,
    damit defusedxml es ablehnt.
    """
    i, n = 0, len(data)
    if data.startswith(b"\xef\xbb\xbf"):
        i = 3
    while i < n:
        if data[i] in _WS:
            i += 1
            continue
        if data.startswith(b"<?", i):
            end = data.find(b"?>", i + 2)
            if end < 0:
                return data
            i = end + 2
            continue
        if data.startswith(b"<!--", i):
            end = data.find(b"-->", i + 4)
            if end < 0:
                return data
            i = end + 3
            continue
        if data.startswith(b"<!DOCTYPE", i):
            end = data.find(b">", i)
            if end < 0:
                return data
            inner = data[i + 9 : end]
            name = inner.strip(b" \t\r\n")
            if not inner[:1] or inner[0] not in _WS or not name:
                return data
            if any(c not in _NAME_CHARS for c in name):
                return data  # internes Subset, SYSTEM, PUBLIC oder Unsinn
            blank = bytes(c if c in (0x0A, 0x0D) else 0x20 for c in data[i : end + 1])
            return data[:i] + blank + data[end + 1 :]
        return data
    return data


def _check_size(data: bytes) -> None:
    if len(data) > MAX_XML_BYTES:
        raise UnsafeXmlError("XML zu gross")


def safe_xml_parse(data: bytes) -> Any:
    """Parst XML vollständig und gibt das Wurzelelement zurück.

    Wirft :class:`UnsafeXmlError` bei DTD/Entities/externen Verweisen und
    :data:`ParseError` bei kaputtem XML.
    """
    _check_size(data)
    try:
        return _det.fromstring(
            neutralize_doctype(data), forbid_dtd=True, forbid_entities=True, forbid_external=True
        )
    except DefusedXmlException as exc:
        raise UnsafeXmlError(type(exc).__name__) from None


def safe_xml_iterparse(data: bytes, events: Sequence[str] = ("end",)) -> Iterator[tuple[str, Any]]:
    """Wie ``iterparse``: liefert ``(event, element)``.

    Bei unvollständigem XML kommen alle Ereignisse bis zur kaputten Stelle,
    danach :data:`ParseError`. Der Aufrufer entscheidet, was er behält.
    """
    _check_size(data)
    src = io.BytesIO(neutralize_doctype(data))
    it = _det.iterparse(src, events=tuple(events), forbid_dtd=True, forbid_entities=True,
                        forbid_external=True)
    while True:
        try:
            item = next(it)
        except StopIteration:
            return
        except DefusedXmlException as exc:
            raise UnsafeXmlError(type(exc).__name__) from None
        yield item


@lru_cache(maxsize=256)
def rx(pattern: str) -> Any:
    """Kompiliert ein re2-Muster (gecacht, ohne Log-Ausgaben)."""
    return re2.compile(pattern, _OPTS)


def clip(text: str, limit: int = MAX_LINE) -> str:
    """Kürzt überlange Zeilen vor dem Scannen."""
    return text if len(text) <= limit else text[:limit]


def decode(data: bytes) -> str:
    """UTF-8 mit Ersatzzeichen; Parser sehen nie rohe Bytes als Text."""
    return data.decode("utf-8", "replace")
