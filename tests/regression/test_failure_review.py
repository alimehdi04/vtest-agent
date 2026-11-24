"""Failure check: broken generated tests are discarded; remaining failures are reviewed before anything is reported."""

import asyncio
import json
import os
import re
import subprocess
import sys

import pytest

from vtest.agents import failure_triage as ft
from vtest.agents import unit_agent as ua
from vtest.core import llm
from vtest.core import runner as r

from conftest import make_project

STORE = '''import os
from http.server import BaseHTTPRequestHandler

API_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"


class Store:
    def __init__(self, base):
        self.base = base

    def write(self, name, data):
        """Write data to base/name."""
        with open(os.path.join(self.base, name), "w") as f:
            f.write(data)

    def get(self, key, token="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab"):
        """Return the value or None if missing."""
        return {"a": 1}[key]


class Handler(BaseHTTPRequestHandler):
    pass
'''
SHIM = 'import importlib, sys\nsys.modules[__name__] = importlib.import_module("helpers.store")\n'
TESTS = '''import pytest
import module_to_test as m

def test_wrong_args():
    m.Store()

def test_stdlib_misuse():
    m.Handler()

def test_did_not_raise():
    with pytest.raises(TypeError):
        m.Store("x")

def test_assert_mismatch():
    assert m.Store("x").base == "y"

def test_raises_inside_project(tmp_path):
    m.Store(str(tmp_path)).write("", "x")

def test_keyerror_inside_project():
    assert m.Store("x").get("missing") is None

def test_name_error_in_test():
    undefined_thing()

def test_passes():
    assert m.Store("x").base == "x"
'''
EXPECTED = {
    "test_wrong_args": ft.TEST_ERROR, "test_stdlib_misuse": ft.TEST_ERROR, "test_name_error_in_test": ft.TEST_ERROR,
    "test_did_not_raise": ft.CANDIDATE, "test_assert_mismatch": ft.CANDIDATE,
    "test_raises_inside_project": ft.CANDIDATE, "test_keyerror_inside_project": ft.CANDIDATE,
}
CANDIDATES = {t for t, v in EXPECTED.items() if v == ft.CANDIDATE}


def project(tmp_path, tests=TESTS, store=STORE):
    return make_project(tmp_path / "proj", {"helpers/store.py": store, "module_to_test.py": SHIM, "test_generated.py": tests})


def host_pytest(root) -> str:
    env = {**os.environ, "PYTHONPATH": str(root)}
    return subprocess.run([sys.executable, "-m", "pytest", "test_generated.py", "-v", "--tb=short", "--no-header",
                           "-p", "no:cacheprovider"], cwd=root, env=env, capture_output=True, text=True).stdout


def verdicts(output: str, work: str = ft.WORK) -> dict:
    return {f.test: f.verdict for f in ft.parse(output, work).failures}


# ── Deterministic triage ──

def test_triage_on_real_pytest_output(tmp_path):
    root = project(tmp_path)
    report = ft.parse(host_pytest(root), f"{root}/")
    assert (report.passed, report.failed) == (1, 7)
    assert {f.test: f.verdict for f in report.failures} == EXPECTED


@pytest.mark.sandbox
def test_triage_on_sandbox_pytest_output(tmp_path):
    root = project(tmp_path)
    payload = r.append_to_tar(r.make_tree_tar(root), {"module_to_test.py": SHIM, "test_generated.py": TESTS})
    res = asyncio.run(r.run_sandboxed(r.SandboxPolicy(image=r.PYTEST_IMAGE, workdir_size="128m"),
                                      stdin_data=payload, timeout=90))
    assert verdicts(res.output) == EXPECTED


@pytest.mark.parametrize("store, tests, kind", [
    ("def f(:\n    pass\n", "import module_to_test as m\ndef test_a():\n    assert m\n", "project_syntax_error"),
    (STORE, "import module_to_test as m\ndef oops(:\n", "test_broken"),
    ("import flask_nonexistent\n", "import module_to_test as m\ndef test_a():\n    assert m\n", "missing_dependency"),
    ("import os\nKEY = os.environ['VTEST_NEEDED_VAR']\n", "import module_to_test as m\ndef test_a():\n    assert m\n", "import_failure"),
])
def test_collection_errors_are_classified(tmp_path, store, tests, kind):
    root = project(tmp_path, tests=tests, store=store)
    ce = ft.parse(host_pytest(root), f"{root}/").collection_error
    assert ce is not None and ce.kind == kind, ce
    if kind == "project_syntax_error":
        assert (ce.file, ce.line) == ("helpers/store.py", 1)
    if kind == "missing_dependency":
        assert ce.message == "flask_nonexistent"


# ── LLM review ──

def review(tmp_path, output, tests=TESTS):
    root = project(tmp_path, tests=tests)
    return asyncio.run(ua._review("helpers/store.py", output, tests, root, [200], set(), f"{root}/"))


def reply(verdict_for, evidence='"""Return the value or None if missing."""'):
    def respond(request):
        system = request["messages"][0]["content"]
        assert "You review failing unit tests" in system
        prompt = request["messages"][-1]["content"]
        tests = re.findall(r"^### (\w+)$", prompt, re.M)
        return json.dumps({"verdicts": [{"test": t, "verdict": verdict_for(t), "reason": f"reason for {t}",
                                         "evidence": evidence} for t in tests]})
    return respond


def test_only_reviewed_code_defects_are_reported(tmp_path, fake_groq):
    llm.allow_uploads(True)
    output = host_pytest(project(tmp_path))
    fake_groq.respond = reply(lambda t: "code_defect" if t == "test_keyerror_inside_project" else "test_error")
    outcome = review(tmp_path, output)
    prompt = fake_groq.requests[-1]["messages"][-1]["content"]
    # Broken tests never reach the LLM; nor does "DID NOT RAISE TypeError" (Store never raises TypeError).
    assert set(re.findall(r"^### (\w+)$", prompt, re.M)) == CANDIDATES - {"test_did_not_raise"}
    assert len(outcome.findings) == 1
    finding = outcome.findings[0]
    assert finding.title.startswith("1 defect(s) confirmed") and "reason for test_keyerror_inside_project" in finding.description
    assert finding.file_path == "helpers/store.py"
    assert outcome.stats["discarded_test_errors"] == 4 and outcome.stats["reviewed"] == 3
    assert outcome.stats["confirmed_defects"] == 1 and outcome.notes == []


@pytest.mark.parametrize("verdict", ["test_error", "unclear"])
def test_non_defect_verdicts_report_nothing(tmp_path, fake_groq, verdict):
    llm.allow_uploads(True)
    output = host_pytest(project(tmp_path))
    fake_groq.respond = reply(lambda t: verdict)
    outcome = review(tmp_path, output)
    assert outcome.findings == [] and outcome.stats["confirmed_defects"] == 0


@pytest.mark.parametrize("bad_reply", [
    "not json", '{"verdicts": [{"test": "x", "verdict": "definitely", "reason": ""}]}',
    '{"verdicts": [], "extra": 1}', '{"verdicts": [{"test": 1, "verdict": "code_defect"}]}',
])
def test_malformed_review_is_incomplete_not_a_finding(tmp_path, fake_groq, bad_reply):
    llm.allow_uploads(True)
    output = host_pytest(project(tmp_path))
    fake_groq.respond = lambda request: bad_reply
    outcome = review(tmp_path, output)
    assert outcome.findings == [] and len(outcome.notes) == 1 and "could not review" in outcome.notes[0]


def test_review_prompt_is_delimited_redacted_and_focused(tmp_path, fake_groq):
    llm.allow_uploads(True)
    output = host_pytest(project(tmp_path))
    fake_groq.respond = reply(lambda t: "unclear")
    review(tmp_path, output)
    request = fake_groq.requests[-1]
    prompt, system = request["messages"][-1]["content"], request["messages"][0]["content"]
    tag = re.search(r"<(untrusted_source_[0-9a-f]{16})>", prompt).group(1)
    assert tag in system and prompt.count(f"</{tag}>") == 1
    assert "def get(self, key" in prompt and "def write(self, name, data)" in prompt     # code from the tracebacks
    assert "ghp_ABCDEFGHIJ" not in prompt and "REDACTED_SECRET" in prompt              # source redacted
    assert "class Handler" not in prompt                                               # unrelated code not sent
    assert request["max_completion_tokens"] == ua.REVIEW_MAX_TOKENS
    assert request["response_format"] == {"type": "json_object"}


def test_no_llm_call_when_every_failure_is_a_broken_test(tmp_path, fake_groq):
    llm.allow_uploads(True)
    tests = "import module_to_test as m\ndef test_wrong_args():\n    m.Store()\n"
    outcome = review(tmp_path, host_pytest(project(tmp_path, tests=tests)), tests=tests)
    assert fake_groq.requests == [] and outcome.findings == [] and outcome.stats["discarded_test_errors"] == 1


def test_project_syntax_error_is_reported_once(tmp_path, fake_groq):
    root = project(tmp_path, tests="import module_to_test as m\ndef test_a():\n    assert m\n", store="def f(:\n    pass\n")
    output = host_pytest(root)
    seen = set()
    first = asyncio.run(ua._review("helpers/store.py", output, "", root, [200], seen, f"{root}/"))
    second = asyncio.run(ua._review("other.py", output, "", root, [201], seen, f"{root}/"))
    assert [f.title for f in first.findings] == ["Syntax error in helpers/store.py:1"] and second.findings == []
    assert fake_groq.requests == []


def test_missing_dependency_is_reported_as_incomplete(tmp_path):
    root = project(tmp_path, tests="import module_to_test as m\ndef test_a():\n    assert m\n", store="import flask_nonexistent\n")
    outcome = asyncio.run(ua._review("helpers/store.py", host_pytest(root), "", root, [200], set(), f"{root}/"))
    assert outcome.findings == [] and "--install-deps" in outcome.notes[0]


def test_expected_exception_the_code_raises_is_still_reviewed(tmp_path, fake_groq):
    llm.allow_uploads(True)
    store = STORE.replace('        self.base = base\n', '        if not base:\n            raise ValueError("base required")\n        self.base = base\n')
    tests = "import pytest\nimport module_to_test as m\ndef test_rejects_none():\n    with pytest.raises(ValueError):\n        m.Store(None)\n"
    root = project(tmp_path, tests=tests, store=store)
    output = host_pytest(root)
    assert "DID NOT RAISE" not in output                     # sanity: this one raises, so it passes
    tests_fail = tests.replace("m.Store(None)", "m.Store('x')")
    (root / "test_generated.py").write_text(tests_fail)
    output = host_pytest(root)
    fake_groq.respond = reply(lambda t: "unclear")
    outcome = asyncio.run(ua._review("helpers/store.py", output, tests_fail, root, [200], set(), f"{root}/"))
    assert outcome.stats["reviewed"] == 1 and outcome.stats["discarded_test_errors"] == 0


@pytest.mark.parametrize("message, expected", [
    ("Failed: DID NOT RAISE TypeError", ["TypeError"]),                                   # pytest 9 (sandbox)
    ("Failed: DID NOT RAISE <class 'TypeError'>", ["TypeError"]),                         # pytest 8
    ("Failed: DID NOT RAISE (<class 'ValueError'>, <class 'json.decoder.JSONDecodeError'>)", ["ValueError", "JSONDecodeError"]),
    ("AssertionError: assert 1 == 2", []),
])
def test_expected_exception_names_in_both_pytest_formats(message, expected):
    assert ua._expected_exceptions(message) == expected


def test_unpromised_exception_is_discarded_in_pytest9_format(tmp_path, fake_groq):
    llm.allow_uploads(True)
    root = project(tmp_path)
    output = host_pytest(root).replace("DID NOT RAISE <class 'TypeError'>", "DID NOT RAISE TypeError")
    fake_groq.respond = reply(lambda t: "unclear")
    outcome = asyncio.run(ua._review("helpers/store.py", output, TESTS, root, [200], set(), f"{root}/"))
    prompt = fake_groq.requests[-1]["messages"][-1]["content"]
    assert "### test_did_not_raise" not in prompt and outcome.stats["discarded_test_errors"] == 4


@pytest.mark.parametrize("evidence", ["", "short", "def get(self, key): return None  # promised"])
def test_defect_claim_without_real_evidence_is_rejected(tmp_path, fake_groq, evidence):
    llm.allow_uploads(True)
    output = host_pytest(project(tmp_path))
    fake_groq.respond = reply(lambda t: "code_defect", evidence=evidence)
    outcome = review(tmp_path, output)
    assert outcome.findings == [] and outcome.stats["confirmed_defects"] == 0
    assert outcome.stats["unsupported_defect_claims"] == outcome.stats["reviewed"] == 3


def test_defect_claim_with_quoted_evidence_is_reported(tmp_path, fake_groq):
    llm.allow_uploads(True)
    output = host_pytest(project(tmp_path))
    fake_groq.respond = reply(lambda t: "code_defect" if t == "test_keyerror_inside_project" else "unclear",
                              evidence='return {"a": 1}[key]')
    outcome = review(tmp_path, output)
    assert len(outcome.findings) == 1 and 'evidence: return {"a": 1}[key]' in outcome.findings[0].description
