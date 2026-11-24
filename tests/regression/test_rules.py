"""vtest rule pack: every annotated case in rule_cases/ is (or is not) flagged; findings carry CWEs; audit rules are hygiene."""

import asyncio
import json
import re
import subprocess
from pathlib import Path

import pytest

from vtest.agents import security_agent as sa

from conftest import HERE, make_project

CASES = HERE / "rule_cases" / "python_web.py"
ANNOTATION = re.compile(r"#\s*(ruleid|ok):\s*([\w-]+)")

pytestmark = pytest.mark.semgrep


def annotations() -> list[tuple[str, str, int]]:
    """(kind, rule id, line the annotation applies to)."""
    out = []
    for no, line in enumerate(CASES.read_text().splitlines(), start=1):
        m = ANNOTATION.search(line)
        if m:
            out.append((m.group(1), m.group(2), no + 1))
    return out


@pytest.fixture(scope="module")
def results():
    out = subprocess.run(
        ["semgrep", "scan", "--config", str(sa.VTEST_RULES), "--metrics=off", "--disable-version-check",
         "--json", "--quiet", "--", CASES.name],
        cwd=CASES.parent, capture_output=True, text=True, check=False)
    report = json.loads(out.stdout)
    assert report["errors"] == [], report["errors"]
    return report["results"]


def test_rule_pack_is_valid():
    out = subprocess.run(["semgrep", "scan", "--validate", "--config", str(sa.VTEST_RULES), "--metrics=off",
                          "--disable-version-check"], capture_output=True, text=True)
    assert "0 configuration error(s)" in out.stdout + out.stderr


@pytest.mark.parametrize("kind, rule, line", annotations(), ids=lambda v: str(v))
def test_annotated_case(results, kind, rule, line):
    flagged = {(r["check_id"].split(".")[-1], r["start"]["line"]) for r in results}
    if kind == "ruleid":
        assert (rule, line) in flagged, f"{rule} should flag line {line}"
    else:
        assert (rule, line) not in flagged, f"{rule} should not flag line {line}"


def test_every_rule_has_positive_and_negative_cases():
    rules = {r["id"] for r in __import__("yaml").safe_load(sa.VTEST_RULES.read_text())["rules"]}
    kinds = {(k, r) for k, r, _ in annotations()}
    missing = sorted(r for r in rules if ("ruleid", r) not in kinds or ("ok", r) not in kinds)
    assert missing == [], f"rules without both a ruleid and an ok case: {missing}"


def test_every_rule_declares_a_cwe(results):
    assert results and all(r["extra"]["metadata"].get("cwe") for r in results)


def test_vtest_rules_run_by_default():
    cmd = sa.build_semgrep_cmd("p/owasp-top-ten", ["a.py"])
    assert str(sa.VTEST_RULES) in cmd and cmd.count("--config") == 2


def test_audit_findings_are_reported_as_low_severity_hygiene(tmp_path, monkeypatch):
    monkeypatch.setattr(sa, "INCLUDE_VTEST_RULES", False)
    rules = tmp_path / "audit.yml"
    rules.write_text(
        "rules:\n  - id: any-eval\n    languages: [python]\n    severity: ERROR\n    message: eval used\n"
        "    metadata: {cwe: ['CWE-95: Eval Injection'], subcategory: [audit], confidence: LOW}\n"
        "    pattern: eval(...)\n")
    repo = make_project(tmp_path / "repo", {"a.py": "def f(x):\n    return eval(x)\n"})
    res = asyncio.run(sa.run(files=[], repo_root=repo, config=str(rules)))
    assert len(res.findings) == 1
    finding = res.findings[0]
    assert finding.severity == sa.Severity.LOW and finding.category == ["Security", "Hygiene"]
