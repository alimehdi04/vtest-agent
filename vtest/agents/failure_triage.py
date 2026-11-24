"""
Triage of failing LLM-generated tests: tell broken tests apart from possible code defects.

Pure functions over pytest's `-v --tb=short` text output; no LLM involved.
A failure whose traceback ends in the test itself (wrong call arguments, broken
test code, a library misused by the test) is a test error and is discarded.
Everything else is a *candidate* defect that still needs review before it is
reported: a failed expectation, or an exception raised inside the project code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

TEST_FILE = "test_generated.py"
SHIM_FILE = "module_to_test.py"
WORK = "/work/"

TEST_ERROR = "test_error"
CANDIDATE = "candidate"

_BLOCK_RE = re.compile(r"^=+ (FAILURES|ERRORS) =+$")
_OTHER_BLOCK_RE = re.compile(r"^=+ .* =+$")
_SECTION_RE = re.compile(r"^_{3,} (.+?) _{3,}$")
_FRAME_RE = re.compile(r"^(\S[^:]*?):(\d+): in (\S+)$")
_EXC_RE = re.compile(r"^E\s+([A-Za-z_][\w.]*):\s?(.*)$")
_SYNTAX_FILE_RE = re.compile(r'^E\s+File "([^"]+)", line (\d+)')
_MISSING_MODULE_RE = re.compile(r"No module named '([^']+)'")
_SIGNATURE_RE = re.compile(
    r"missing \d+ required|takes \d+ positional|positional arguments? but \d+|"
    r"unexpected keyword argument|got multiple values for argument|takes no arguments"
)
_BROKEN_TEST_EXC = ("NameError", "ImportError", "ModuleNotFoundError", "SyntaxError", "IndentationError")


@dataclass
class Frame:
    path: str
    line: int
    func: str
    kind: str                      # test | shim | project | external


@dataclass
class Failure:
    test: str
    phase: str                     # call | setup | teardown
    frames: list[Frame]
    exc_type: str
    message: str
    details: str
    verdict: str = ""
    reason: str = ""


@dataclass
class CollectionError:
    kind: str                      # project_syntax_error | test_broken | missing_dependency | import_failure
    message: str
    file: str | None = None
    line: int | None = None


@dataclass
class PytestReport:
    passed: int = 0
    failed: int = 0
    errors: int = 0
    collection_error: CollectionError | None = None
    failures: list[Failure] = field(default_factory=list)


def _rel(path: str, work: str = WORK) -> str:
    return path[len(work):] if path.startswith(work) else path


def frame_kind(path: str, work: str = WORK) -> str:
    rel = _rel(path, work)
    if rel == TEST_FILE:
        return "test"
    if rel == SHIM_FILE:
        return "shim"
    # pytest prints files under its rootdir (/work, the project tree) as relative paths.
    if not rel.startswith(("/", "<")):
        return "project"
    return "external"


def _count(output: str, word: str) -> int:
    for line in reversed(output.splitlines()):
        if re.match(r"^=+ .* in [\d.]+s", line):
            m = re.search(rf"(\d+) {word}", line)
            return int(m.group(1)) if m else 0
    return 0


def _sections(output: str) -> list[tuple[str, list[str]]]:
    """(title, body lines) for every section inside the FAILURES / ERRORS blocks."""
    sections, current, in_block = [], None, False
    for line in output.splitlines():
        if _BLOCK_RE.match(line):
            in_block = True
            continue
        if _OTHER_BLOCK_RE.match(line):
            in_block = False
            current = None
            continue
        if not in_block:
            continue
        m = _SECTION_RE.match(line)
        if m:
            current = (m.group(1).strip(), [])
            sections.append(current)
        elif current is not None:
            current[1].append(line)
    return sections


def _parse_body(body: list[str], work: str) -> tuple[list[Frame], str, str, str]:
    frames = [Frame(_rel(m.group(1), work), int(m.group(2)), m.group(3), frame_kind(m.group(1), work))
              for m in map(_FRAME_RE.match, body) if m]
    e_lines = [line for line in body if line.startswith("E ")]
    exc = next((m for m in map(_EXC_RE.match, e_lines) if m), None)
    exc_type = exc.group(1) if exc else ""
    message = f"{exc.group(1)}: {exc.group(2)}".strip() if exc else (e_lines[0][1:].strip() if e_lines else "")
    return frames, exc_type, message, "\n".join(e_lines)[:1500]


def parse(output: str, work: str = WORK) -> PytestReport:
    """`work` is the project root as pytest sees it (the sandbox's /work)."""
    report = PytestReport(passed=_count(output, "passed"), failed=_count(output, "failed"),
                          errors=_count(output, r"errors?"))
    for title, body in _sections(output):
        frames, exc_type, message, details = _parse_body(body, work)
        if title.startswith("ERROR collecting"):
            report.collection_error = _classify_collection(frames, exc_type, message, body, work)
            continue
        phase, test = "call", title
        m = re.match(r"ERROR at (setup|teardown) of (.+)", title)
        if m:
            phase, test = m.group(1), m.group(2)
        report.failures.append(Failure(test=test.split("[")[0], phase=phase, frames=frames,
                                       exc_type=exc_type, message=message, details=details))
    for f in report.failures:
        f.verdict, f.reason = classify(f)
    return report


def classify(f: Failure) -> tuple[str, str]:
    """Deterministic verdict: TEST_ERROR (discard) or CANDIDATE (needs review)."""
    if f.phase != "call" and "fixture" in f.details and "not found" in f.details:
        return TEST_ERROR, "the test uses a pytest fixture that isn't available"
    frames = [fr for fr in f.frames if fr.kind != "shim"]
    if not frames:
        return (TEST_ERROR, "the test failed before reaching the code") if f.phase != "call" else \
               (CANDIDATE, "no traceback; the expectation was not met")
    deepest = frames[-1]
    if deepest.kind == "test":
        if f.exc_type == "TypeError" and _SIGNATURE_RE.search(f.message):
            return TEST_ERROR, "the test called the code with the wrong arguments"
        if f.exc_type in _BROKEN_TEST_EXC:
            return TEST_ERROR, "the generated test code is broken"
        if f.exc_type == "AttributeError" and "'NoneType'" not in f.message:
            return TEST_ERROR, "the test uses an attribute the code doesn't have"
        return CANDIDATE, "the code's behaviour didn't match the test's expectation"
    if deepest.kind == "external":
        caller = next((fr for fr in reversed(frames) if fr.kind != "external"), None)
        if caller is None or caller.kind == "test":
            return TEST_ERROR, "the test misused a library"
        return CANDIDATE, "a library call made by the project code failed"
    return CANDIDATE, "an exception was raised inside the project code"


def _classify_collection(frames, exc_type, message, body, work: str) -> CollectionError:
    syntax = next((m for m in map(_SYNTAX_FILE_RE.match, body) if m), None)
    if syntax:
        rel = _rel(syntax.group(1), work)
        if PurePosixPath(rel).name == TEST_FILE or rel.endswith("/" + TEST_FILE):
            return CollectionError("test_broken", message)
        return CollectionError("project_syntax_error", message, file=rel, line=int(syntax.group(2)))
    origin = next((fr for fr in reversed(frames) if fr.kind in ("test", "project")), None)
    if origin is None or origin.kind == "test":
        return CollectionError("test_broken", message)
    if exc_type in ("ModuleNotFoundError", "ImportError"):
        missing = _MISSING_MODULE_RE.search(message)
        return CollectionError("missing_dependency", missing.group(1) if missing else message, file=origin.path)
    return CollectionError("import_failure", message, file=origin.path, line=origin.line)
