"""Hilfen für die Export-Tests: echter Daemon mit Auswertung und das Fixture MS2."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from tests.integration.test_daemon_ingest import run

__all__ = ["run", "read_tree", "unsafe_markdown", "OWN_SECRET"]

from tests.core.conftest import OWN_SECRET  # noqa: E402


def read_tree(root: Path) -> dict[str, bytes]:
    """Alle Dateien eines Exports (relativer Pfad -> Bytes); Symlinks gibt es nicht."""
    out: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        assert not p.is_symlink(), p
        if p.is_file():
            out[p.relative_to(root).as_posix()] = p.read_bytes()
    return out


_FENCE = re.compile(r"^(`{3,}|~{3,})(.*)$")


def _outside_code(md: str) -> list[str]:
    """Zeilen ausserhalb von Codeblöcken (für die Prüfung auf Markdown-Steuerzeichen)."""
    lines: list[str] = []
    fence: str | None = None
    for ln in md.split("\n"):
        m = _FENCE.match(ln)
        if fence is None and m:
            fence = m.group(1)
            continue
        if fence is not None:
            if ln == fence:
                fence = None
            continue
        lines.append(ln)
    assert fence is None, "offener Codeblock"
    return lines


def _unescaped(line: str, chars: str) -> list[str]:
    hits = []
    i = 0
    while i < len(line):
        if line[i] == "\\":
            i += 2
            continue
        if line[i] in chars:
            hits.append(line[i])
        i += 1
    return hits


def unsafe_markdown(md: str) -> list[str]:
    """Befunde: HTML, Bilder, Embeds, externe Links, Inline-Code, ``$=``, Steuerzeichen."""
    bad: list[str] = []
    for ch in md:
        cp = ord(ch)
        if (cp < 0x20 and ch not in "\n\t") or 0x7F <= cp <= 0x9F or ch in "‪‫‬‭‮⁦⁧⁨⁩​‌‍‎‏﻿  ":
            bad.append(f"Steuerzeichen U+{cp:04X}")
    for ln in _outside_code(md):
        if _unescaped(ln, "<"):
            bad.append(f"HTML möglich: {ln[:80]}")
        if _unescaped(ln, "`"):
            bad.append(f"Inline-Code: {ln[:80]}")
        if _unescaped(ln, "$"):
            bad.append(f"Dollar: {ln[:80]}")
        if re.search(r"(?<!\\)!(?<!\\)\[", ln):
            bad.append(f"Bild oder Embed: {ln[:80]}")
        for m in re.finditer(r"(?<!\\)\]\(([^)]*)\)", ln):
            target = m.group(1)
            if "://" in target or target.startswith(("/", "..", "mailto:", "javascript:", "data:")):
                bad.append(f"Link nach aussen: {target[:80]}")
        if re.search(r"(?i)\b[a-z][a-z0-9+.-]*://", ln):
            bad.append(f"URL: {ln[:80]}")
        if re.search(r"(?i)\bwww\.", ln):
            bad.append(f"www: {ln[:80]}")
    return bad


def sync_any(d: Any) -> Any:
    from tests.web.api.helpers import sync

    return sync(d)
