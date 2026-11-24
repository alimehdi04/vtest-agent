"""Security agent (L1, Phase 0 scan coverage) and the CLI end to end (exit codes, consent, redaction in a full run)."""

import asyncio
import subprocess
import xml.etree.ElementTree as ET

import pytest
from typer.testing import CliRunner

import vtest.main as cli
from vtest.agents import security_agent as sa

from conftest import RULES, make_project

VULNERABLE = "import subprocess\n\ndef ping(host):\n    return subprocess.run('ping ' + host, shell=True)\n"


def flat(text: str) -> str:
    return " ".join(text.split())


# ── L1: Semgrep invocation ──

def test_semgrep_command_is_pinned_and_telemetry_free():
    cmd = sa.build_semgrep_cmd("p/owasp-top-ten", ["a.py"])
    assert cmd[cmd.index("--config") + 1] == "p/owasp-top-ten"
    assert "--metrics=off" in cmd and "--disable-version-check" in cmd and "auto" not in cmd
    assert cmd[-2:] == ["--", "a.py"]                   # targets can't be parsed as flags


@pytest.mark.parametrize("config", ["auto", "--config=auto", "https://evil.example/rules.yml", "/nonexistent/rules", "p/../x"])
def test_semgrep_config_rejects_unsafe_values(config):
    with pytest.raises(sa.SemgrepConfigError):
        sa.resolve_semgrep_config(config)


def test_semgrep_config_rejects_symlink_and_accepts_local_dir(tmp_path):
    (tmp_path / "rules").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "rules")
    assert sa.resolve_semgrep_config(str(tmp_path / "rules")) == str((tmp_path / "rules").resolve())
    with pytest.raises(sa.SemgrepConfigError):
        sa.resolve_semgrep_config(str(tmp_path / "link"))


def test_semgrep_errors_are_summarised():
    msg = sa._describe_errors([{"type": "Timeout", "path": "a.py"}, {"type": ["PartialParsing", []], "path": "b.py"},
                               {"type": "Timeout", "path": "a.py"}])
    assert "2 Timeout" in msg and "1 PartialParsing" in msg and "a.py" in msg


def test_target_collection_honours_gitignore_and_skips_symlinks(tmp_path):
    repo = make_project(tmp_path / "repo", {
        "src/app.py": "x = 1\n", "tests/test_app.py": "x = 1\n", "venv/lib.py": "x = 1\n",
        "generated/out.py": "x = 1\n", ".gitignore": "generated/\n",
    })
    (repo / "link.py").symlink_to("/etc/passwd")
    assert sa.collect_targets(repo) == [".gitignore", "src/app.py", "tests/test_app.py"]


# ── Phase 0: Semgrep must not silently skip tests/ ──

@pytest.mark.semgrep
def test_code_under_tests_dir_of_a_git_repo_is_scanned(tmp_path):
    repo = make_project(tmp_path / "repo", {"README.md": "x\n", "tests/fixture/ping.py": VULNERABLE})
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    res = asyncio.run(sa.run(files=[], repo_root=repo, config=str(RULES)))
    assert res.error is None
    assert [f.file_path for f in res.findings] == ["tests/fixture/ping.py"]
    assert "Analyzed" in res.summary


@pytest.mark.semgrep
def test_scan_that_analyzes_nothing_is_an_error(tmp_path):
    repo = make_project(tmp_path / "repo", {"notes.txt": "nothing to analyze\n"})
    res = asyncio.run(sa.run(files=[], repo_root=repo, config=str(RULES)))
    assert res.findings == [] and res.error and "0 of 1" in res.summary


# ── CLI: exit codes and incomplete runs ──

def invoke(*args):
    return CliRunner().invoke(cli.app, list(args))


@pytest.mark.semgrep
def test_analyze_succeeds_and_marks_run_complete(tmp_path, fake_groq):
    repo = make_project(tmp_path / "repo", {"ping.py": VULNERABLE})
    res = invoke("analyze", str(repo), "--semgrep-config", str(RULES))
    assert res.exit_code == 0, res.output
    assert fake_groq.clients == [] and fake_groq.requests == []         # M5: no consent, no Groq
    root = ET.parse(repo / "output" / "fix-brief.md").getroot()
    assert root.find("run_status").get("complete") == "true"
    assert len(root.findall(".//finding")) == 1


def test_analyze_with_failing_agent_exits_1_and_reports_incomplete(tmp_path):
    repo = make_project(tmp_path / "repo", {"ping.py": VULNERABLE})
    res = invoke("analyze", str(repo), "--semgrep-config", str(tmp_path / "missing.yml"))
    assert res.exit_code == 1, res.output
    assert "Incomplete run" in flat(res.output) and "No issues found" not in res.output
    assert ET.parse(repo / "output" / "fix-brief.md").getroot().find("run_status").get("complete") == "false"
    assert "Incomplete run" in (repo / "output" / "audit-report.md").read_text()


@pytest.mark.semgrep
def test_security_command_exit_codes(tmp_path):
    repo = make_project(tmp_path / "repo", {"ping.py": VULNERABLE})
    ok = invoke("security", str(repo), "--semgrep-config", str(RULES))
    assert ok.exit_code == 0 and "Found 1 security issues" in flat(ok.output)
    bad = invoke("security", str(repo), "--semgrep-config", str(tmp_path / "missing.yml"))
    assert bad.exit_code == 1 and "Incomplete scan" in flat(bad.output)


# ── Full run with consent: secrets never reach the prompt, the sandbox gets the real code ──

CREDS = '''import os

DB_PASSWORD = os.environ.get("DB_PASSWORD")


def connect(url="postgres://admin:S3cretPassw0rd@db.internal/app", token="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"):
    """Connect. Fallback api_key = "sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" """
    return url, token
'''
CREDS_TEST = '''import inspect, module_to_test as m
def test_real_secret_in_sandbox():
    assert "S3cretPassw0rd" in inspect.signature(m.connect).parameters["url"].default
def test_force_finding():
    assert False
'''


@pytest.mark.semgrep
@pytest.mark.sandbox
def test_full_run_with_consent_redacts_prompts_and_tests_real_code(tmp_path, fake_groq):
    repo = make_project(tmp_path / "repo", {"creds.py": CREDS, "ping.py": VULNERABLE})

    def respond(request):
        if request.get("response_format"):
            return '{"run_unit": true, "run_security": true, "run_stress": false, "reasoning": "ok"}'
        if "labelled 'creds.py'" in request["messages"][-1]["content"]:
            return CREDS_TEST
        return "import module_to_test\ndef test_ok():\n    assert True\n"

    fake_groq.respond = respond
    res = invoke("analyze", str(repo), "--allow-llm-upload", "--semgrep-config", str(RULES))
    assert res.exit_code == 0, res.output
    prompts = "\n".join(r["messages"][-1]["content"] for r in fake_groq.requests)
    assert not [s for s in ("S3cretPassw0rd", "ghp_ABCDEFGHIJ", "sk-proj-AbCd") if s in prompts]
    assert "postgres://admin:REDACTED_SECRET@db.internal" in prompts
    brief = (repo / "output" / "fix-brief.md").read_text()
    assert "test_real_secret_in_sandbox PASSED" in brief
    assert fake_groq.clients and all(c["api_key"] == "gsk_FAKE_TEST_KEY_canary" for c in fake_groq.clients)
