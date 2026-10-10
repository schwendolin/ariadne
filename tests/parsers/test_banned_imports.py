"""Parser-Module importieren weder xml.etree, xml.dom, lxml noch das Standard-``re``.

XML nur über ``ariadne.parsers.safe`` (defusedxml), Regex nur über ``re2``
(Architektur 5.6). Geprüft wird der Quelltext (AST), damit auch spät oder
bedingt ausgeführte Importe auffallen.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import ariadne.parsers

PARSER_DIR = Path(ariadne.parsers.__file__).parent
MODULES = sorted(PARSER_DIR.glob("*.py"))
BANNED = ("xml", "lxml", "re", "sre_compile", "sre_parse", "_sre", "regex")
DYNAMIC = {"__import__", "import_module", "exec", "eval"}


def _banned(name: str) -> bool:
    return any(name == b or name.startswith(b + ".") for b in BANNED)


@pytest.mark.parametrize("path", MODULES, ids=lambda p: p.name)
def test_no_banned_imports(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not _banned(alias.name), f"{path.name}: import {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            assert node.level == 0 or not _banned(mod), f"{path.name}: from .{mod}"
            assert not _banned(mod), f"{path.name}: from {mod} import ..."
        elif isinstance(node, ast.Call):
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            assert name not in DYNAMIC, f"{path.name}: dynamischer Import/Code über {name}()"


def test_all_parser_modules_checked() -> None:
    names = {p.name for p in MODULES}
    for expected in (
        "safe.py",
        "nmap_xml.py",
        "nmap_text.py",
        "regex_net.py",
        "listener_callback.py",
        "registry.py",
    ):
        assert expected in names


def test_checker_catches_violations(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    for src in (
        "import re\n",
        "from xml.etree import ElementTree\n",
        "import lxml.etree\n",
        "import importlib\nimportlib.import_module('re')\n",
    ):
        bad.write_text(src)
        with pytest.raises(AssertionError):
            test_no_banned_imports(bad)
