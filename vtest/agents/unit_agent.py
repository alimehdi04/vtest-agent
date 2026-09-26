"""
Unit Test Agent
===============
Pipeline (per research blueprint):
  1. For each source file, build an AST skeleton (function signatures only)
     and send to Groq (Llama 3.1) — not the full file body (Repomix / tree-sitter lesson)
  2. Groq (Llama 3.1) generates a complete pytest suite
  3. LLM output is cleaned and validated before execution
  4. Tests run in an isolated tmp directory (not inside the user's repo)
  5. stdout/stderr captured via async runner with timeout + circular buffer (Cline lesson)
  6. Results parsed into typed Finding objects (Instructor / Pydantic lesson)
  7. Raw log wrapped for PR-Agent-style <details> collapsing in the report
"""

import ast
import asyncio
import re
import tempfile
from pathlib import Path

from vtest.core.llm import ask
from vtest.core.models import AgentResult, AgentType, Finding, Severity
from vtest.core.runner import SubprocessError, run_command

# MAX_FILES      = 10
MAX_FILES = 50
MAX_FILE_BYTES = 40_000


def _extract_skeleton(source: str) -> str:
    """
    Return only function/class signatures from Python source.
    Falls back to raw source if AST parse fails.
    Implements Repomix tree-sitter compression lesson (~70% token reduction).
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source[:3000]

    lines = source.splitlines()
    skeleton: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1
            sig_lines: list[str] = []
            for i in range(start, min(start + 10, len(lines))):
                sig_lines.append(lines[i])
                if lines[i].rstrip().endswith(":"):
                    break
            skeleton.append("\n".join(sig_lines))
            if ast.get_docstring(node):
                skeleton.append(f'    """{ast.get_docstring(node)}"""')
            skeleton.append("    ...")

        elif isinstance(node, ast.ClassDef):
            skeleton.append(f"class {node.name}:")
            if ast.get_docstring(node):
                skeleton.append(f'    """{ast.get_docstring(node)}"""')

    return "\n\n".join(skeleton) if skeleton else source[:3000]


def _clean_llm_code(raw: str) -> str:
    """Strip markdown fences the LLM may add despite instructions."""
    raw = raw.strip()
    raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw)
    raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()


def _generate_tests(skeleton: str, filename: str) -> str:
    """Ask Groq (Llama 3.1) to write a pytest suite for the given code skeleton."""
    system = (
        "You are an expert Python testing engineer. "
        "You write thorough, executable pytest suites. "
        "Return ONLY raw Python code — no markdown fences, no explanations."
    )
    prompt = f"""
Write a complete pytest test suite for the following Python code from '{filename}'.

STRICT RULES:
1. The code under test will be placed in a file named `module_to_test.py` in the same directory.
2. You MUST import everything you test from `module_to_test`.
3. Cover: happy path, edge cases (None, empty, zero, negative), and type errors.
4. Use descriptive test function names (test_<function>_<scenario>).
5. Return ONLY the raw Python code. No markdown, no explanation.

Code skeleton:
{skeleton}
""".strip()

    return ask(prompt, system=system, temperature=0.1)


def _parse_pytest_output(output: str, file_path: str, issue_id: str) -> Finding | None:
    """
    Parse pytest stdout into a Finding.
    Returns None if all tests passed.
    """
    lines = output.splitlines()

    passed = failed = error = 0
    for line in lines:
        m = re.search(r"(\d+) passed", line)
        if m:
            passed = int(m.group(1))
        m = re.search(r"(\d+) failed", line)
        if m:
            failed = int(m.group(1))
        m = re.search(r"(\d+) error", line)
        if m:
            error = int(m.group(1))

    if failed == 0 and error == 0:
        return None

    failing_tests: list[str] = []
    for line in lines:
        if line.startswith("FAILED ") or line.startswith("ERROR "):
            failing_tests.append(line.strip())

    first_assertion = ""
    for i, line in enumerate(lines):
        if "AssertionError" in line or "assert " in line.lower():
            first_assertion = lines[i].strip()
            break

    severity = Severity.CRITICAL if error > 0 else (Severity.HIGH if failed >= 3 else Severity.MEDIUM)

    description = (
        f"{failed} test(s) failed, {error} error(s). "
        + (f"e.g. {first_assertion}" if first_assertion else "")
    ).strip()

    return Finding(
        id=issue_id,
        title=f"{failed} unit test(s) failing in {Path(file_path).name}",
        description=description,
        severity=severity,
        agent=AgentType.UNIT,
        file_path=file_path,
        line=None,
        category=["Unit test"],
        log=output,
        fix_hint=(
            f"Fix the following failing tests in {Path(file_path).name}: "
            + "; ".join(failing_tests[:5])
        ),
    )


async def _run_tests_for_file(
    source_file: Path,
    repo_root: Path,
    issue_counter: list[int],
) -> Finding | None:
    """Generate tests for one file, run them, return a Finding or None."""
    try:
        source = source_file.read_text(errors="ignore")
    except OSError:
        return None

    if len(source.encode()) > MAX_FILE_BYTES:
        source = source[:MAX_FILE_BYTES]

    skeleton = _extract_skeleton(source)
    raw_tests = _generate_tests(skeleton, source_file.name)
    test_code = _clean_llm_code(raw_tests)

    if not test_code or "import" not in test_code:
        return None

    with tempfile.TemporaryDirectory(prefix="vtest_unit_") as tmp:
        tmp_path = Path(tmp)

        (tmp_path / "module_to_test.py").write_text(source)
        (tmp_path / "test_generated.py").write_text(test_code)

        try:
            returncode, output = await run_command(
                cmd=["python3", "-m", "pytest", "test_generated.py", "-v", "--tb=short", "--no-header"],
                cwd=tmp_path,
                timeout=60,
                check=False, # <--- Allows pytest exit code 1 to be parsed
            )
        except SubprocessError as e:
            return Finding(
                id=f"{issue_counter[0]:02d}",
                title=f"Unit agent subprocess error — {source_file.name}",
                description=str(e),
                severity=Severity.INFO,
                agent=AgentType.UNIT,
                file_path=str(source_file.relative_to(repo_root)),
                line=None,
                category=["Unit test"], # <--- Added category
                log=str(e),
                fix_hint="",
            )

        rel_path = str(source_file.relative_to(repo_root))
        issue_id = f"{issue_counter[0]:02d}"

        finding = _parse_pytest_output(output, rel_path, issue_id)
        if finding:
            issue_counter[0] += 1
        return finding


async def run(
    files: list[Path],
    repo_root: Path,
    start_id: int = 1,
) -> AgentResult:
    """
    Entry point called by the orchestrator.

    Args:
        files:     Source files from the ingestion layer (Python only).
        repo_root: Root of the repo being tested.
        start_id:  Starting issue ID counter (so IDs don't clash across agents).

    Returns:
        AgentResult with all findings and a plain-English summary.
    """
    python_files = [
        f for f in files
        if f.suffix == ".py"
        and "test" not in f.name.lower()
        and f.stat().st_size > 0
    ][:MAX_FILES]

    if not python_files:
        return AgentResult(
            agent=AgentType.UNIT,
            findings=[],
            summary="No Python source files found to test.",
        )

    issue_counter = [start_id]

    tasks = [
        _run_tests_for_file(f, repo_root, issue_counter)
        for f in python_files
    ]

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    findings: list[Finding] = []
    errors: list[str] = []

    for result in raw_results:
        if isinstance(result, Exception):
            errors.append(str(result))
        elif result is not None:
            findings.append(result)

    total_files = len(python_files)
    total_issues = len(findings)
    severity_counts = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    summary_parts = [f"Tested {total_files} file(s). Found {total_issues} issue(s)."]
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if sev in severity_counts:
            summary_parts.append(f"{severity_counts[sev]} {sev.value}")
    if errors:
        summary_parts.append(f"{len(errors)} agent error(s).")

    return AgentResult(
        agent=AgentType.UNIT,
        findings=findings,
        summary=" ".join(summary_parts),
        error="; ".join(errors) if errors else None,
    )