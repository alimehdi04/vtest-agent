"""
vtest evaluation harness.

    python3 -m evaluation.run owasp                 # Security agent, OWASP Benchmark Python (tune + held-out)
    python3 -m evaluation.run sample                # Security/Unit/Stress agents on tests/sample_codebase (uses Groq)
    python3 -m evaluation.run rescore-brief PATH    # rescore an existing fix-brief.md on the tune split

Results go to evaluation/results/<UTC timestamp>-<suite>/ (metrics.json + scorecard.md).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import platform
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from evaluation import owasp, sample
from evaluation.scoring import MODES, ci, pct, pts

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "tests/benchmark/BenchmarkPython"
MANIFEST = ROOT / "tests/benchmark/benchmark-results/dataset-manifest.csv"
RULES = ROOT / "tests/benchmark/benchmark-results/owasp-top-ten-rules.yaml"
SAMPLE = ROOT / "tests/sample_codebase"


def _cmd(args: list[str]) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=60, cwd=ROOT).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def metadata(suite: str, config: str) -> dict:
    cfg = Path(config)
    return {
        "suite": suite,
        "started_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "vtest_commit": _cmd(["git", "rev-parse", "HEAD"]),
        "vtest_tracked_changes": bool(_cmd(["git", "status", "--porcelain", "--untracked-files=no"])),
        "semgrep_version": _cmd(["semgrep", "--version", "--disable-version-check"]).splitlines()[-1:] or [""],
        "semgrep_config": str(config),
        "semgrep_config_sha256": hashlib.sha256(cfg.read_bytes()).hexdigest() if cfg.is_file() else None,
        "python": platform.python_version(),
    }


# ── scorecards ──────────────────────────────────────────────────────────────

def _overall_rows(split: str, res: dict) -> list[str]:
    rows = []
    for mode in MODES:
        m = res["overall"][mode]
        rows.append(f"| {split} | {mode} | {m['n']} | {m['TP']} | {m['FP']} | {m['TN']} | {m['FN']} | "
                    f"{pct(m['recall'])} ({ci(m['recall_ci95'])}) | {pct(m['false_positive_rate'])} ({ci(m['fpr_ci95'])}) | "
                    f"{pct(m['precision'])} | **{pts(m['youden'])}** |")
    return rows


def owasp_card(meta: dict, data: dict) -> str:
    lines = [f"# vtest scorecard: OWASP Benchmark Python (Security agent)", "",
             f"- Commit `{meta['vtest_commit'][:10]}`{' (+ uncommitted changes)' if meta['vtest_tracked_changes'] else ''}, "
             f"Semgrep {meta['semgrep_version'][0]}, rules `{Path(meta['semgrep_config']).name}`"
             f"{' + vtest rule pack' if meta.get('vtest_rules') else ' only (no vtest rule pack)'}",
             f"- Score = recall − FPR (Youden; 0 = random guessing). Modes: `file` = any finding on the case file; "
             f"`cwe` = finding's CWE in the case's CWE family; `cwe-strict` = exact CWE.",
             f"- Report the **test** split (525 held-out cases never used for rule writing). "
             f"`dev` (525) and `tune` (180) are used to develop rules.", "",
             "| Split | Mode | n | TP | FP | TN | FN | Recall (95% CI) | FPR (95% CI) | Precision | Score |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for split in ("test", "dev", "tune"):
        lines += _overall_rows(split, data[split])
    lines += ["", "## Test split by category", "",
              "| Category | CWE | Vulnerable | Safe | Recall (file) | FPR (file) | Score (file) | Recall (cwe) | FPR (cwe) | Score (cwe) |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for cat, r in data["test"]["per_category"].items():
        f, c = r["file"], r["cwe"]
        lines.append(f"| {cat} | {r['cwe_id']} | {f['TP'] + f['FN']} | {f['FP'] + f['TN']} | {pct(f['recall'])} | "
                     f"{pct(f['false_positive_rate'])} | {pts(f['youden'])} | {pct(c['recall'])} | "
                     f"{pct(c['false_positive_rate'])} | **{pts(c['youden'])}** |")
    lines += ["", "## Test split: rules by how well they separate vulnerable from safe cases", "",
              "| Rule | Confidence | Subcategory | Vulnerable cases hit | Safe cases hit | Score |",
              "|---|---|---|---|---|---|"]
    for r in data["test"]["rules"][:25]:
        lines.append(f"| {r['rule']} | {r['confidence']} | {r['subcategory']} | {r['vulnerable_hits']} | "
                     f"{r['safe_hits']} | {pts(r['youden'])} |")
    lines += ["", f"Scan: {data['scan']['summary']} Elapsed {data['elapsed_seconds']:.0f}s."]
    return "\n".join(lines) + "\n"


def sample_card(meta: dict, data: dict) -> str:
    lines = [f"# vtest scorecard: tests/sample_codebase", "",
             f"- Commit `{meta['vtest_commit'][:10]}`{' (+ uncommitted changes)' if meta['vtest_tracked_changes'] else ''}, "
             f"Semgrep {meta['semgrep_version'][0]}, rules `{Path(meta['semgrep_config']).name}`",
             "- No safe twins in this dataset: files without a ground-truth label are weak negatives.", ""]
    s = data.get("security")
    if s and "error" not in s:
        lines += [f"## Security agent: {s['detected_cwe_level']}/{s['total']} vulnerabilities detected with the right CWE "
                  f"({s['detected_file_level']}/{s['total']} with any finding in the file)", "",
                  "| File | CWE | Cross-file | Any finding | Right CWE | Rules |", "|---|---|---|---|---|---|"]
        for r in s["vulnerabilities"]:
            lines.append(f"| {r['file']} | {r['cwe']} | {'yes' if r['cross_file'] else ''} | {'✓' if r['file_hit'] else '✗'} | "
                         f"{'✓' if r['cwe_hit'] else '✗'} | {', '.join(r['rules'])} |")
        lines += ["", f"Findings in files with no labelled vulnerability: {len(s['hits_outside_vulnerable_files'])}", ""]
    elif s:
        lines += [f"## Security agent: error: {s['error']}", ""]
    u = data.get("unit")
    if u:
        lines += [f"## Unit agent", "",
                  f"- Files attempted: {u['files_attempted']}; runnable tests: **{u['files_with_runnable_tests']}**; "
                  f"collection errors: {u['collection_errors']}; not run (LLM/rate limit/no code): {u['files_not_run']}",
                  f"- Files with failing tests: {u.get('files_with_failing_tests', '–')} → reported after review: "
                  f"labelled **{u['labelled_files_flagged']}/{u['labelled_files']}**, "
                  f"unlabelled **{u['unlabelled_files_flagged']}/{u['unlabelled_files']}** (lower is better)",
                  f"- Agent: {u['agent_summary']}", "",
                  "| File | Label | Outcome | Passed | Failed | Discarded | Reviewed | Confirmed | Reported | First error |",
                  "|---|---|---|---|---|---|---|---|---|---|"]
        for r in u["files"]:
            lines.append(f"| {r['file']} | {r['label']} | {r['state']} | {r.get('passed', '')} | {r.get('failed', '')} | "
                         f"{r.get('discarded_test_errors', '')} | {r.get('reviewed', '')} | {r.get('confirmed_defects', '')} | "
                         f"{'✓' if r.get('reported') else ''} | {r.get('first_error', '').replace('|', '/')[:90]} |")
        if u.get("findings"):
            lines += ["", "Reported findings (check the reasons by hand):", ""]
            lines += [f"- **{f['file']}**: {f['title']}: {f['description'][:400]}" for f in u["findings"]]
        lines.append("")
    st = data.get("stress")
    if st:
        lines += [f"## Stress agent: {st['correct']}/{st['total']} latency verdicts correct", "",
                  "| Module | Slow endpoint expected | Latency flagged | Failure-rate flagged | Summary |", "|---|---|---|---|---|"]
        for r in st["runs"]:
            lines.append(f"| {r['module']} | {r['expected_latency_finding']} | {r['latency_flagged']} | "
                         f"{r['failure_rate_flagged']} | {(r['summary'] + ' ' + r['error']).strip()[:160]} |")
    return "\n".join(lines) + "\n"


def rescore_card(path: str, data: dict) -> str:
    lines = [f"# Rescore of `{path}` (tune split)", "",
             "| Split | Mode | n | TP | FP | TN | FN | Recall (95% CI) | FPR (95% CI) | Precision | Score |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    return "\n".join(lines + _overall_rows("tune", data)) + "\n"


# ── suites ──────────────────────────────────────────────────────────────────
#
# Datasets are scanned from a temporary copy outside any git repository. Semgrep's
# default ignore list skips tests/, test/, build/, dist/ and vendor/ paths relative to
# the git root, and reports them as neither scanned nor skipped, so scanning
# vtest-agent/tests/... in place would silently find nothing.

def staged_copy(src: Path, tmp: str) -> Path:
    dst = Path(tmp) / src.name
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "output"))
    return dst


async def run_owasp(args) -> dict:
    cases = owasp.load_cases(BENCH)
    tune = owasp.load_tune_ids(MANIFEST)
    dev, test = owasp.split_heldout(cases, set(cases) - tune)
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="vtest-eval-") as tmp:
        hits, scan = await owasp.run_security_agent(staged_copy(BENCH / "testcode", tmp), args.config, args.timeout)
    return {"scan": scan, "elapsed_seconds": time.perf_counter() - t0,
            "test": owasp.score(cases, hits, test), "dev": owasp.score(cases, hits, dev),
            "tune": owasp.score(cases, hits, tune),
            "hits": hits}


async def run_sample(args) -> dict:
    gt = sample.load_ground_truth(SAMPLE)
    data = {}
    with tempfile.TemporaryDirectory(prefix="vtest-eval-") as tmp:
        root = staged_copy(SAMPLE, tmp)
        if "security" in args.agents:
            data["security"] = await sample.security(root, gt, args.config)
        if "unit" in args.agents:
            data["unit"] = await sample.unit(root, gt)
        if "stress" in args.agents:
            data["stress"] = await sample.stress(root, gt)
    return data


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("suite", choices=["owasp", "sample", "rescore-brief"])
    p.add_argument("brief", nargs="?", help="fix-brief.md to rescore (rescore-brief only)")
    p.add_argument("--config", default=str(RULES), help="Semgrep config (default: vendored owasp-top-ten snapshot)")
    p.add_argument("--timeout", type=int, default=1800, help="Semgrep timeout in seconds (owasp)")
    p.add_argument("--agents", default="security,unit,stress", help="sample suite: comma-separated agents")
    p.add_argument("--out", default=str(ROOT / "evaluation/results"))
    p.add_argument("--without-vtest-rules", action="store_true",
                   help="Scan with the --config ruleset only (baseline without vtest's rule pack)")
    args = p.parse_args()
    args.agents = set(args.agents.split(","))
    from vtest.agents import security_agent
    security_agent.INCLUDE_VTEST_RULES = not args.without_vtest_rules

    meta = metadata(args.suite, args.config)
    meta["vtest_rules"] = None if args.without_vtest_rules else hashlib.sha256(security_agent.VTEST_RULES.read_bytes()).hexdigest()
    t0 = time.perf_counter()
    if args.suite == "owasp":
        data = asyncio.run(run_owasp(args))
        card = owasp_card(meta, data)
    elif args.suite == "sample":
        data = asyncio.run(run_sample(args))
        card = sample_card(meta, data)
    else:
        if not args.brief:
            p.error("rescore-brief needs the path to a fix-brief.md")
        cases = owasp.load_cases(BENCH)
        data = owasp.score(cases, owasp.hits_from_brief(Path(args.brief)), owasp.load_tune_ids(MANIFEST))
        card = rescore_card(args.brief, data)
    meta["elapsed_seconds"] = round(time.perf_counter() - t0, 1)

    out = Path(args.out) / f"{meta['started_utc'].replace(':', '').replace('+0000', 'Z')}-{args.suite}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "metrics.json").write_text(json.dumps({"metadata": meta, "results": data}, indent=2, default=list) + "\n")
    (out / "scorecard.md").write_text(card)
    print(card)
    print(f"Saved: {out}")


if __name__ == "__main__":
    main()
