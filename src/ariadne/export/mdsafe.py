"""Encoder für die Senke «Markdown im Export» (E13, Architektur 8.7 Punkte 2, 3, 5).

Genau ein Encoder pro Senke: Alles, was aus Zieldaten, aus KI-Texten oder aus Texten des Menschen
stammt (Titel, Beschreibung eines Findings), geht durch :func:`md_text` (eine Zeile) oder
:func:`md_lines` (mehrere Zeilen) oder steht in einem Codeblock aus :func:`code_block`. Feste Texte
der Vorlagen brauchen das nicht.

* Steuer-, Bidi-, Zero-Width- und Tag-Zeichen werden sichtbar (``<ESC>``, ``<U+202E>``).
* Jedes Zeichen mit Bedeutung in CommonMark, GFM oder Obsidian bekommt einen Backslash
  (Klammern, ``!``, Backtick, ``$``, ``%``, ``=``, ``^``, ``#``, ``<``, ``>``, ``|``, ``*``, ``_``,
  ``~``, ``&``, ``{``, ``}``, ``:``, ``@`` …): kein Link, kein Bild, kein Embed, kein HTML, kein
  ``$=``-Inline-Code, keine Tabelle, keine Überschrift aus Zieldaten.
* URLs werden entschärft (``http[:]//``, ``www[.]``), damit Viewer sie nicht selbst verlinken.
* Inline-Code gibt es für Zieldaten nie; Codeblöcke haben den Info-String ``text`` und eine Fence
  aus Backticks, die länger ist als jede Backtick- oder Tilde-Folge im Inhalt.
"""

from __future__ import annotations

import re
import unicodedata

from ariadne.termsafe import visible

__all__ = ["md_text", "md_lines", "code_block", "slug", "short_id", "visible_line"]

# ASCII-Satzzeichen mit Bedeutung in CommonMark, GFM, Obsidian (Highlights ==, Kommentare %%,
# Tags #, Fussnoten ^, Wikilinks [[ ]], Embeds ![[ ]], Mathe $, Dataview $=, Callouts >).
_SPECIAL = frozenset("\\`*_{}[]()<>#-!|~$%=^&:@")
_URL = re.compile(r"(?i)\b([a-z][a-z0-9+.-]{1,20})://")
_WWW = re.compile(r"(?i)\bwww\.")
_SEPARATORS = {"\u2028": "<U+2028>", "\u2029": "<U+2029>"}


def visible_line(text: str) -> str:
    """Eine Zeile ohne unsichtbare oder steuernde Zeichen (auch LF, CR, Tab werden sichtbar)."""
    out = visible(text)
    for ch, rep in _SEPARATORS.items():
        out = out.replace(ch, rep)
    return out


def _defang(text: str) -> str:
    text = _URL.sub(lambda m: m.group(1) + "[:]//", text)
    return _WWW.sub(lambda m: m.group(0)[:3] + "[.]", text)


def md_text(value: object, max_len: int = 2000) -> str:
    """Eine Zeile Zieldaten als harmloser Markdown-Text."""
    text = value if isinstance(value, str) else str(value)
    text = unicodedata.normalize("NFC", text)
    if max_len > 0 and len(text) > max_len:
        text = text[:max_len] + " [gekürzt]"
    text = _defang(visible_line(text))
    out: list[str] = []
    for ch in text:
        if ch in _SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def md_lines(value: object, max_lines: int = 200) -> str:
    """Mehrere Zeilen (Beschreibung, Massnahme): jede Zeile wie :func:`md_text`, als eigene Zeile
    mit hartem Umbruch. Leere Zeilen trennen Absätze."""
    text = value if isinstance(value, str) else str(value)
    lines = text.replace("\r\n", "\n").split("\n")
    if len(lines) > max_lines:
        lines = [*lines[:max_lines], "[gekürzt]"]
    out = [md_text(ln) if ln.strip() else "" for ln in lines]
    return "\\\n".join(out).replace("\\\n\\\n", "\n\n")


def code_block(text: str, *, info: str = "text") -> str:
    """Codeblock mit Info-String ``text`` und einer Fence, die länger ist als jede Backtick- oder
    Tilde-Folge im Inhalt. Jede Zeile ist sichtbar gemacht (Tab bleibt)."""
    lines = [visible_line(ln).replace("<TAB>", "\t") for ln in text.split("\n")]
    body = "\n".join(lines)
    longest = max((len(m.group(0)) for m in re.finditer(r"`+|~+", body)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{info}\n{body}\n{fence}"


def slug(value: object, default: str = "x") -> str:
    """Slug aus ``[a-z0-9-]{1,40}`` für Dateinamen (nie Zieldaten im Namen, nur dieser Auszug)."""
    text = unicodedata.normalize("NFKD", str(value)).encode("ascii", "ignore").decode().lower()
    s = re.sub(r"[^a-z0-9]+", "-", text).strip("-")[:40].strip("-")
    return s or default


def short_id(value: object) -> str:
    """Kurze, stabile Kennung (8 Hex) aus einer internen ID, für Dateinamen."""
    import hashlib

    return hashlib.sha256(str(value).encode("utf-8", "surrogateescape")).hexdigest()[:8]
