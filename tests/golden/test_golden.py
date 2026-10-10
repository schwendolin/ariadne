"""Golden-Runner für Parser (Architektur 10.2).

Jeder Fall liegt in ``tests/golden/<parser-id>/<fall>/``:

* ``input.*``: Rohdaten (Datei-Inhalt oder Terminalausgabe),
* ``meta.toml``: ``tool``, ``version``, ``command``, ``source``
  («nachgestellt» oder «echt») und ``[unit]`` (kind, cmd, path, sniff, mime,
  ``[unit.context]``); optional ``match = false`` für Fälle, die der Parser
  nicht annehmen darf,
* ``expected.jsonl``: kanonisch sortierte Ausgabe (eine JSON-Zeile pro
  Beobachtung/Mention, bei Abbruch ``{"error": "<Klasse>"}``).

``--update-golden`` zeigt den Diff und schreibt danach ``expected.jsonl``.
"""

from __future__ import annotations

import difflib
import json
import tomllib
from pathlib import Path

import pytest

from ariadne.parsers.registry import ALL_PARSERS
from tests.parsers.helpers import item_dicts, make_unit

GOLDEN = Path(__file__).parent
CASES = sorted(p for p in GOLDEN.glob("*/*") if (p / "meta.toml").is_file())


def load_case(case: Path) -> tuple[dict, object]:
    meta = tomllib.loads((case / "meta.toml").read_text(encoding="utf-8"))
    inputs = sorted(case.glob("input.*"))
    assert len(inputs) == 1, f"{case}: genau eine input.*-Datei erwartet"
    raw = inputs[0].read_bytes()
    u = dict(meta.get("unit", {}))
    kind = u.get("kind", "command")
    common = dict(
        kind=kind,
        cmd=u.get("cmd"),
        path=u.get("path"),
        sniff=u.get("sniff"),
        mime=u.get("mime"),
        context=u.get("context"),
        unit_id=f"golden:{case.parent.name}/{case.name}",
    )
    if kind == "file":
        unit = make_unit(data=raw, **common)
    else:
        unit = make_unit(raw.decode("utf-8"), **common)
    return meta, unit


def render(parser: object, unit: object) -> list[str]:
    try:
        items = list(parser.parse(unit))  # type: ignore[attr-defined]
    except Exception as exc:  # Abbruch ist ein erwartbares Ergebnis (z. B. DTD)
        return [json.dumps({"error": type(exc).__name__}, sort_keys=True)]
    return sorted(json.dumps(d, sort_keys=True, ensure_ascii=False) for d in item_dicts(items))


def test_cases_exist():
    ids = {c.parent.name for c in CASES}
    assert set(ALL_PARSERS) <= ids, "jeder eingebaute Parser braucht Golden-Fälle"


@pytest.mark.parametrize("case", CASES, ids=lambda p: f"{p.parent.name}/{p.name}")
def test_golden(case: Path, update_golden: bool, capsys: pytest.CaptureFixture[str]) -> None:
    meta, unit = load_case(case)
    assert meta.get("source") in ("nachgestellt", "echt"), "meta.toml: source fehlt"
    for key in ("tool", "version", "command"):
        assert meta.get(key), f"meta.toml: {key} fehlt"
    parser = ALL_PARSERS[case.parent.name]()
    if meta.get("match", True):
        assert parser.match(unit) > 0, "Parser nimmt die Einheit nicht an"
    else:
        assert parser.match(unit) == 0
        return
    actual = render(parser, unit)
    path = case / "expected.jsonl"
    expected = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    if actual == expected:
        return
    diff = "\n".join(
        difflib.unified_diff(expected, actual, f"{case.name}/expected.jsonl", "aktuell", lineterm="")
    )
    if update_golden:
        with capsys.disabled():
            print(f"\n--- Golden {case.parent.name}/{case.name} wird neu geschrieben ---\n{diff}")
        path.write_text("".join(line + "\n" for line in actual), encoding="utf-8")
        return
    pytest.fail(f"Golden-Abweichung (mit --update-golden übernehmen):\n{diff}")
