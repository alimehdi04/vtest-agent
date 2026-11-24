"""
Shared fixtures for vtest's regression suite.

Markers:
  sandbox  needs Podman/Docker and the vtest sandbox images (`vtest sandbox-build`)
  semgrep  needs `semgrep` on PATH

Tests with a marker are skipped automatically when the requirement is missing.
No test calls the real Groq API.
"""

import asyncio
import shutil
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

HERE = Path(__file__).resolve().parent
RULES = HERE / "rules.yml"           # tiny offline Semgrep ruleset


def _sandbox_ready() -> bool:
    try:
        from vtest.core import runner

        async def check() -> bool:
            rt = await runner.detect_runtime()
            return await runner.image_exists(runner.PYTEST_IMAGE, rt) and await runner.image_exists(runner.K6_IMAGE, rt)

        return asyncio.run(check())
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    sandbox_ok = _sandbox_ready() if any("sandbox" in i.keywords for i in items) else True
    semgrep_ok = shutil.which("semgrep") is not None
    for item in items:
        if "sandbox" in item.keywords and not sandbox_ok:
            item.add_marker(pytest.mark.skip(reason="no container runtime or sandbox images (run `vtest sandbox-build`)"))
        if "semgrep" in item.keywords and not semgrep_ok:
            item.add_marker(pytest.mark.skip(reason="semgrep not installed"))


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    """Private cache dir, a fake Groq key, and LLM consent reset around every test."""
    from vtest.core import llm

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg-cache"))
    monkeypatch.setenv("GROQ_API_KEY", "gsk_FAKE_TEST_KEY_canary")
    monkeypatch.setenv("COLUMNS", "200")
    llm.allow_uploads(False)
    yield
    llm.allow_uploads(False)


@pytest.fixture
def fake_groq(monkeypatch):
    """
    Replace the Groq client. Set `calls.respond = fn(request) -> str | Exception`
    to control replies; every client and request is recorded.
    """
    calls = NS(clients=[], requests=[], respond=lambda request: "ok", finish_reason="stop")

    class FakeClient:
        def __init__(self, **kwargs):
            calls.clients.append(kwargs)
            self.chat = NS(completions=NS(create=self._create))

        def _create(self, **request):
            calls.requests.append(request)
            reply = calls.respond(request)
            if isinstance(reply, BaseException):
                raise reply
            return NS(choices=[NS(message=NS(content=reply), finish_reason=calls.finish_reason)])

    monkeypatch.setattr("vtest.core.llm.Groq", FakeClient)
    return calls


def make_project(root: Path, files: dict[str, str]) -> Path:
    """Write {relative path: content} under root and return the resolved root."""
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return root.resolve()
