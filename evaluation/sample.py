"""
tests/sample_codebase: score the Security, Unit and Stress agents against ground_truth.json.

Caveat: the dataset has no safe twins. Files with no ground-truth entry are used as
weak negatives, so false-positive numbers here are indicative only.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from evaluation.scoring import cwe_match, cwe_numbers

SKIP = {"test_benchmark.py"}
# The CWE-22 taint source for module3_utils lives here; it is neither a positive nor a clean negative.
AMBIGUOUS = {"module3_main.py"}


def load_ground_truth(root: Path) -> dict:
    gt = json.loads((root / "ground_truth.json").read_text())
    files = sorted(p.name for p in root.glob("*.py") if p.name not in SKIP)
    positives = {v["file"] for v in gt["vulnerabilities"]} | {d["file"] for d in gt["defects"]}
    negatives = [f for f in files if f not in positives and f not in AMBIGUOUS]
    return {**gt, "py_files": files, "negatives": negatives}


async def security(root: Path, gt: dict, config: str) -> dict:
    from vtest.agents import security_agent

    result = await security_agent.run(files=[], repo_root=root, config=config)
    if result.error:
        return {"error": result.error}
    hits = []
    for f in result.findings:
        md = json.loads(f.log).get("extra", {}).get("metadata", {})
        hits.append({"file": Path(f.file_path).name, "line": f.line, "rule": f.title.split(".")[-1],
                     "cwes": sorted(cwe_numbers(md.get("cwe")))})
    rows = []
    for v in gt["vulnerabilities"]:
        expected = int(v["cwe"].split("-")[1])
        in_file = [h for h in hits if h["file"] == v["file"]]
        rows.append({"file": v["file"], "cwe": v["cwe"], "cross_file": bool(v.get("cross_file")),
                     "file_hit": bool(in_file),
                     "cwe_hit": any(cwe_match(set(h["cwes"]), expected, "cwe") for h in in_file),
                     "rules": sorted({h["rule"] for h in in_file})})
    vuln_files = {v["file"] for v in gt["vulnerabilities"]}
    return {
        "vulnerabilities": rows,
        "detected_file_level": sum(r["file_hit"] for r in rows),
        "detected_cwe_level": sum(r["cwe_hit"] for r in rows),
        "total": len(rows),
        "hits_outside_vulnerable_files": [h for h in hits if h["file"] not in vuln_files],
    }


def _classify(output: str) -> dict:
    """Outcome of one sandboxed pytest run."""
    def count(word):
        m = re.findall(rf"(\d+) {word}", output)
        return int(m[-1]) if m else 0
    collection_error = bool(re.search(r"error(s)? during collection|ERROR collecting|Interrupted:", output))
    passed, failed, errors = count("passed"), count("failed"), count(r"errors?")
    if collection_error or (errors and not passed and not failed):
        state = "collection_error"
    elif failed or errors:
        state = "failing_tests"
    elif passed:
        state = "all_passed"
    else:
        state = "no_tests_run"
    first_error = next((l.strip() for l in output.splitlines() if l.startswith("E ")), "")
    return {"state": state, "passed": passed, "failed": failed, "errors": errors, "first_error": first_error[:200]}


async def unit(root: Path, gt: dict) -> dict:
    """Run the Unit agent and record every pytest outcome, including all-pass runs it doesn't report."""
    from vtest.agents import unit_agent
    from vtest.core.llm import allow_uploads

    allow_uploads(True)
    unit_agent.CACHE_ENABLED = False          # measure fresh LLM generation, not cached tests
    outcomes: dict[str, dict] = {}
    original = unit_agent._review

    async def recording_review(rel_path, output, *args, **kwargs):
        outcome = await original(rel_path, output, *args, **kwargs)
        outcomes[Path(rel_path).name] = {**_classify(output), **{k: outcome.stats.get(k, 0) for k in
                                         ("discarded_test_errors", "reviewed", "confirmed_defects")},
                                         "reported": bool(outcome.findings)}
        return outcome

    unit_agent._review = recording_review
    try:
        files = [root / f for f in gt["py_files"]]
        result = await unit_agent.run(files=files, repo_root=root)
    finally:
        unit_agent._review = original

    attempted = [f for f in gt["py_files"] if "test" not in f.lower()]
    defect_files = {d["file"]: d["kind"] for d in gt["defects"]} | {v["file"]: "security" for v in gt["vulnerabilities"]}
    rows = []
    for f in attempted:
        o = outcomes.get(f, {"state": "not_run (LLM error or no usable code)", "reported": False})
        rows.append({"file": f, "label": defect_files.get(f, "ambiguous" if f in AMBIGUOUS else "none"), **o})
    usable = [r for r in rows if r["state"] in ("all_passed", "failing_tests")]
    positives = [r for r in rows if r["label"] not in ("none", "ambiguous")]
    negatives = [r for r in rows if r["label"] == "none"]
    return {
        "files_attempted": len(rows),
        "files_with_runnable_tests": len(usable),
        "files_not_run": sum(r["state"].startswith("not_run") for r in rows),
        "collection_errors": sum(r["state"] == "collection_error" for r in rows),
        "files_with_failing_tests": sum(r["state"] == "failing_tests" for r in rows),
        # A file counts as flagged only when the agent reported a finding for it (after review).
        "labelled_files_flagged": sum(r["reported"] for r in positives),
        "labelled_files": len(positives),
        "unlabelled_files_flagged": sum(r["reported"] for r in negatives),
        "unlabelled_files": len(negatives),
        "agent_summary": result.summary,
        "findings": [{"file": f.file_path, "title": f.title, "description": f.description} for f in result.findings],
        "agent_errors": (result.error or "")[:1500],
        "files": rows,
    }


async def stress(root: Path, gt: dict) -> dict:
    """module5 has a CPU-bound endpoint (expected: latency finding); module4 is the control."""
    from vtest.agents import stress_agent

    cases = [("module5_main.py", True), ("module4_main.py", False)]
    out = []
    files = [root / f for f in gt["py_files"]]
    for module, expect_slow in cases:
        port = gt["servers"][module]
        res = await stress_agent.run(files=files, repo_root=root, start_id=300, port=port,
                                     app_cmd=["python3", module])
        titles = [f.title for f in res.findings]
        out.append({"module": module, "port": port, "expected_latency_finding": expect_slow,
                    "latency_flagged": any(t.startswith("High API Latency") for t in titles),
                    "failure_rate_flagged": any(t.startswith("High request failure rate") for t in titles),
                    "summary": res.summary, "error": (res.error or "")[:800], "findings": titles})
    return {"runs": out,
            "correct": sum(r["latency_flagged"] == r["expected_latency_finding"] for r in out),
            "total": len(out)}
