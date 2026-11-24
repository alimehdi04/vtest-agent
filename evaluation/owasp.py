"""
OWASP Benchmark for Python: score vtest's Security agent.

Splits: "tune" = the 180 cases in the existing dataset manifest (already used for
diagnosis); "heldout" = the other 1,050 cases. Report held-out numbers as the result.
"""

from __future__ import annotations

import collections
import csv
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from evaluation.scoring import MODES, confusion, cwe_match, cwe_numbers

CASE_RE = re.compile(r"BenchmarkTest\d{5}")


def load_cases(bench_dir: Path) -> dict[str, dict]:
    """expectedresults-0.1.csv -> {case_id: {category, vulnerable, cwe}}"""
    cases = {}
    with (bench_dir / "expectedresults-0.1.csv").open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            case_id, category, real, cwe = (x.strip() for x in row[:4])
            cases[case_id] = {"category": category, "vulnerable": real == "true", "cwe": int(cwe)}
    return cases


def load_tune_ids(manifest: Path) -> set[str]:
    with manifest.open(encoding="utf-8") as fh:
        return {row["case_id"] for row in csv.DictReader(fh)}


def _hit(case_id: str, issue: dict) -> dict:
    md = issue.get("extra", {}).get("metadata", {})
    sub = md.get("subcategory", [])
    return {
        "case": case_id,
        "rule": str(issue.get("check_id", "")).split(".")[-1],
        "cwes": sorted(cwe_numbers(md.get("cwe"))),
        "subcategory": sub if isinstance(sub, list) else [sub],
        "confidence": md.get("confidence", ""),
    }


def hits_from_findings(findings) -> list[dict]:
    """vtest Finding objects from the Security agent -> hits (Semgrep JSON is in Finding.log)."""
    hits = []
    for f in findings:
        m = CASE_RE.search(f.file_path or "")
        if m:
            hits.append(_hit(m.group(), json.loads(f.log)))
    return hits


def hits_from_brief(path: Path) -> list[dict]:
    """Security findings from an existing vtest fix-brief.md."""
    hits = []
    for f in ET.parse(path).getroot().iter("finding"):
        m = CASE_RE.search(f.findtext("location") or "")
        if f.get("agent") == "Security" and m:
            hits.append(_hit(m.group(), json.loads(f.findtext("execution_trace"))))
    return hits


def score(cases: dict, hits: list[dict], ids: set[str]) -> dict:
    by_case = collections.defaultdict(list)
    for h in hits:
        by_case[h["case"]].append(h)

    def predicted(cid: str, mode: str) -> bool:
        return any(cwe_match(set(h["cwes"]), cases[cid]["cwe"], mode) for h in by_case[cid])

    out = {"cases": len(ids), "overall": {}, "per_category": {}, "rules": []}
    for mode in MODES:
        out["overall"][mode] = confusion([(cases[c]["vulnerable"], predicted(c, mode)) for c in ids])
    for cat in sorted({cases[c]["category"] for c in ids}):
        sub = [c for c in ids if cases[c]["category"] == cat]
        out["per_category"][cat] = {
            "cwe_id": f"CWE-{cases[sub[0]]['cwe']}",
            **{mode: confusion([(cases[c]["vulnerable"], predicted(c, mode)) for c in sub]) for mode in ("file", "cwe")},
        }
    # Which rules separate vulnerable from safe cases, and which fire on both.
    rule_stats = collections.defaultdict(lambda: {"vuln_cases": set(), "safe_cases": set(), "confidence": "", "subcategory": ""})
    for c in ids:
        for h in by_case[c]:
            st = rule_stats[h["rule"]]
            (st["vuln_cases"] if cases[c]["vulnerable"] else st["safe_cases"]).add(c)
            st["confidence"], st["subcategory"] = h["confidence"], ",".join(h["subcategory"])
    n_vuln = sum(cases[c]["vulnerable"] for c in ids)
    n_safe = len(ids) - n_vuln
    for rule, st in rule_stats.items():
        v, s = len(st["vuln_cases"]), len(st["safe_cases"])
        out["rules"].append({"rule": rule, "confidence": st["confidence"], "subcategory": st["subcategory"],
                             "vulnerable_hits": v, "safe_hits": s,
                             "youden": v / n_vuln - s / n_safe if n_vuln and n_safe else None})
    out["rules"].sort(key=lambda r: -(r["vulnerable_hits"] + r["safe_hits"]))
    return out


async def run_security_agent(testcode_dir: Path, config: str, timeout: int) -> tuple[list[dict], dict]:
    """Run vtest's own Security agent over the benchmark's testcode directory."""
    from vtest.agents import security_agent

    security_agent.SEMGREP_TIMEOUT = timeout          # product default (300s) is too short for 1,230 files
    result = await security_agent.run(files=[], repo_root=testcode_dir, config=config)
    if result.error:
        raise RuntimeError(f"Security agent failed: {result.error}")
    return hits_from_findings(result.findings), {"findings": len(result.findings), "summary": result.summary}
