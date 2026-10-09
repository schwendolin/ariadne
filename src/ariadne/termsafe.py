"""Encoder für Ausgaben ins Terminal. Nur Standardbibliothek.

Sicherheitsprinzip 2 (Architektur 9.2): Jede Senke hat genau einen Encoder.
``term_safe`` ist Pflicht für alles, was Shim und CLI ins Terminal schreiben und
was aus Zieldaten stammen kann (Hostnamen, Titel, Dateinamen, Benutzer).
"""

from __future__ import annotations

import unicodedata

__all__ = ["term_safe", "visible"]

# Bidi-Steuerzeichen, Zero-Width-Zeichen und ähnliche unsichtbare Formatierer.
_INVISIBLE = {
    0x061C,  # ARABIC LETTER MARK
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
    0x2066, 0x2067, 0x2068, 0x2069,
    0xFEFF,
}
_NAMES = {0x1B: "ESC", 0x07: "BEL", 0x08: "BS", 0x7F: "DEL", 0x0D: "CR", 0x0A: "LF", 0x09: "TAB"}


def _escape_char(cp: int) -> str:
    name = _NAMES.get(cp)
    if name:
        return f"<{name}>"
    if cp <= 0xFF:
        return f"<0x{cp:02X}>"
    return f"<U+{cp:04X}>"


def visible(text: str) -> str:
    """Macht Steuer-, Bidi-, Zero-Width- und Tag-Zeichen sichtbar, ohne zu kürzen."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if (
            cp < 0x20
            or cp == 0x7F
            or 0x80 <= cp <= 0x9F
            or cp in _INVISIBLE
            or 0xE0000 <= cp <= 0xE007F  # Unicode-Tag-Zeichen
            or unicodedata.category(ch) in ("Cf", "Cs", "Co", "Cn")
        ):
            out.append(_escape_char(cp))
        else:
            out.append(ch)
    return "".join(out)


def term_safe(value: object, max_len: int = 200) -> str:
    """Sichere Textdarstellung für das Terminal.

    Nur druckbare Zeichen, alles andere sichtbar ersetzt, Länge begrenzt.
    Das Ergebnis enthält garantiert kein ESC, kein C0/C1 und kein DEL.
    """
    text = value if isinstance(value, str) else str(value)
    safe = visible(text)
    if max_len > 0 and len(safe) > max_len:
        safe = safe[: max(0, max_len - 1)] + "…"
    return safe
