# import subprocess
# import json

# def run_security_scan(target_path: str) -> list:
#     """
#     Runs Semgrep locally, hunting for vulnerabilities and secrets.
#     Returns a list of cleanly parsed findings.
#     """
#     findings = []
#     try:
        
#         # check=False because Semgrep returns a non-zero exit code if it finds vulnerabilities!
#         # Run semgrep with auto-config, output as JSON, and ignore third-party dirs
#         result = subprocess.run(
#             [
#                 "semgrep", "scan", "--config", "auto", "--json",
#                 "--exclude", "venv",
#                 "--exclude", "node_modules",
#                 "--exclude", ".git",
#                 "--exclude", "__pycache__",
#                 target_path
#             ],
#             capture_output=True,
#             text=True,
#             check=False 
#         )
        
#         if not result.stdout:
#             return []
            
#         data = json.loads(result.stdout)
        
#         for index, error in enumerate(data.get("results", [])):
#             # Map Semgrep's severity string to our visual report scale
#             raw_sev = error.get("extra", {}).get("severity", "INFO")
#             mapped_sev = "High" if raw_sev == "ERROR" else "Medium" if raw_sev == "WARNING" else "Low"
            
#             # Truncate the message for the summary table
#             full_msg = error.get("extra", {}).get("message", "Security issue detected.")
#             short_msg = full_msg.split(".")[0] if "." in full_msg else full_msg[:60]
            
#             findings.append({
#                 "id": f"SEC-{index+1:02d}",
#                 "issue": short_msg,
#                 "severity": mapped_sev,
#                 "category": "Security",
#                 "file_line": f"{error.get('path')}:{error.get('start', {}).get('line')}",
#                 "agent": "Security",
#                 "raw_log": full_msg
#             })
            
#         return findings
        
#     except FileNotFoundError:
#         return [{"id": "ERR", "issue": "Semgrep not installed", "severity": "Critical", "category": "System", "file_line": "N/A", "agent": "Security"}]
#     except json.JSONDecodeError:
#         return [{"id": "ERR", "issue": "Failed to parse Semgrep output", "severity": "High", "category": "System", "file_line": "N/A", "agent": "Security"}]

import collections
import json
import os
import re
from pathlib import Path

from vtest.core.ingestion import _get_pathspec
from vtest.core.models import AgentResult, AgentType, Finding, Severity
from vtest.core.runner import TREE_SKIP_DIRS, SubprocessError, run_tool

# Targets are passed to Semgrep explicitly, in chunks, so that Semgrep's built-in
# ignore list (tests/, test/, build/, vendor/ ... relative to the git root) can't
# silently drop files: explicitly listed files are always scanned.
TARGET_CHUNK = 4000

# Semgrep's JSON report for a large repository can be tens of MB. Semgrep is a
# trusted host tool, so it gets a higher cap than sandboxed output (1 MB).
SEMGREP_MAX_OUTPUT = 64 * 1024 * 1024
SEMGREP_TIMEOUT = 300

# L1: an explicit, pinned ruleset instead of "--config auto" (which requires metrics
# and sends project metadata to pick rules). Note that "p/..." is a Semgrep Registry
# pack: its rules are still downloaded from semgrep.dev, but no telemetry is sent.
# For a fully offline scan, pass a vendored rules file or directory (--semgrep-config).
DEFAULT_SEMGREP_CONFIG = "p/owasp-top-ten"
_REGISTRY_PACK_RE = re.compile(r"^p/[a-z0-9][a-z0-9-]{0,63}$")


class SemgrepConfigError(ValueError):
    pass


def resolve_semgrep_config(config: str) -> str:
    """
    Accept either a registry pack id ("p/owasp-top-ten") or a local rules file
    or directory (not a symlink). Anything else (URLs, "auto", other flags) is rejected.
    """
    config = (config or "").strip()
    if _REGISTRY_PACK_RE.fullmatch(config):
        return config
    path = Path(config).expanduser()
    if config.startswith("-") or "://" in config or not path.exists():
        raise SemgrepConfigError(f"Semgrep config must be a registry pack (p/<name>) or an existing local path: {config!r}")
    if path.is_symlink():
        raise SemgrepConfigError(f"Semgrep config must not be a symlink: {config!r}")
    if not (path.is_file() or path.is_dir()):
        raise SemgrepConfigError(f"Semgrep config is not a file or directory: {config!r}")
    return str(path.resolve())


def collect_targets(repo_root: Path) -> list[str]:
    """Regular files under repo_root (relative paths), honoring .gitignore and vtest's skip list; no symlinks."""
    spec = _get_pathspec(repo_root)
    targets = []
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        rel_root = os.path.relpath(root, repo_root)
        dirs[:] = sorted(
            d for d in dirs
            if d not in TREE_SKIP_DIRS
            and not os.path.islink(os.path.join(root, d))
            and not spec.match_file(os.path.normpath(os.path.join(rel_root, d)) + "/")
        )
        for name in sorted(files):
            rel = os.path.normpath(os.path.join(rel_root, name))
            full = os.path.join(root, name)
            if os.path.islink(full) or not os.path.isfile(full) or spec.match_file(rel):
                continue
            targets.append(rel)
    return targets


def build_semgrep_cmd(config: str, targets: list[str] | None = None) -> list[str]:
    return [
        "semgrep",
        "scan",
        "--config", resolve_semgrep_config(config),
        "--metrics=off",                 # L1: no telemetry
        "--disable-version-check",       # L1: no version-check request
        "--exclude", "venv",
        "--exclude", ".venv",
        "--exclude", "node_modules",
        "--json",
        "--quiet",
        "--",
        *(targets or []),
    ]


def _describe_errors(errors: list[dict]) -> str:
    kinds = collections.Counter()
    for e in errors:
        kind = e.get("type")
        kinds[kind if isinstance(kind, str) else (kind[0] if isinstance(kind, list) and kind else "error")] += 1
    paths = sorted({p for e in errors for p in ([e.get("path")] if e.get("path") else [])})
    shown = ", ".join(f"{n} {k}" for k, n in kinds.most_common())
    return f"Semgrep could not fully analyze the code ({shown})" + (f"; files: {', '.join(paths[:5])}" if paths else "")


async def run(
    files: list[Path],
    repo_root: Path,
    start_id: int = 1,
    config: str = DEFAULT_SEMGREP_CONFIG,
) -> AgentResult:
    """
    Runs Semgrep on the host (trusted tool, static analysis only) and maps findings to Pydantic models.
    """
    findings = []

    try:
        resolve_semgrep_config(config)
    except SemgrepConfigError as e:
        return AgentResult(
            agent=AgentType.SECURITY, findings=[], summary="Security scan not run: invalid Semgrep config.", error=str(e)
        )

    targets = collect_targets(repo_root)
    if not targets:
        return AgentResult(agent=AgentType.SECURITY, findings=[], summary="Security scan: no files to scan.")

    semgrep_findings: list[dict] = []
    semgrep_errors: list[dict] = []
    scanned: set[str] = set()
    for start in range(0, len(targets), TARGET_CHUNK):
        cmd = build_semgrep_cmd(config, targets[start:start + TARGET_CHUNK])
        try:
            res = await run_tool(cmd, cwd=repo_root, timeout=SEMGREP_TIMEOUT, max_output=SEMGREP_MAX_OUTPUT)
        except SubprocessError as e:
            return AgentResult(
                agent=AgentType.SECURITY,
                findings=[],
                summary="Security scan failed to execute.",
                error=f"Semgrep execution error: {e}"
            )

        # Exit 0 = clean, 1 = findings reported. Anything else is a Semgrep error.
        if res.returncode not in (0, 1):
            return AgentResult(
                agent=AgentType.SECURITY,
                findings=[],
                summary="Security scan failed to execute.",
                error=f"Semgrep exited with code {res.returncode}: {res.stderr.strip()[-1500:]}"
            )
        if res.truncated:
            return AgentResult(
                agent=AgentType.SECURITY,
                findings=[],
                summary="Security scan output was too large to parse.",
                error=f"Semgrep output exceeded {SEMGREP_MAX_OUTPUT} bytes."
            )

        try:
            report = json.loads(res.stdout)
        except json.JSONDecodeError:
            return AgentResult(
                agent=AgentType.SECURITY,
                findings=[],
                summary="Failed to parse Semgrep output.",
                error="Output was not valid JSON."
            )
        semgrep_findings.extend(report.get("results", []))
        semgrep_errors.extend(report.get("errors", []))
        scanned.update(report.get("paths", {}).get("scanned", []))

    # Never report a clean result for a scan that analyzed nothing.
    if not scanned:
        return AgentResult(
            agent=AgentType.SECURITY,
            findings=[],
            summary=f"Security scan analyzed 0 of {len(targets)} file(s).",
            error="Semgrep scanned no files (none matched the ruleset's languages, or all were skipped).",
        )
    
    def map_severity(sg_sev: str) -> Severity:
        sg_sev = sg_sev.upper()
        if sg_sev == "ERROR": return Severity.CRITICAL
        if sg_sev == "WARNING": return Severity.HIGH
        if sg_sev == "INFO": return Severity.LOW
        return Severity.MEDIUM

    issue_id = start_id
    for issue in semgrep_findings:
        finding = Finding(
            id=f"{issue_id:02d}",
            title=issue.get("check_id", "Vulnerability Detected"),
            description=issue.get("extra", {}).get("message", "No description provided."),
            severity=map_severity(issue.get("extra", {}).get("severity", "INFO")),
            agent=AgentType.SECURITY,
            file_path=issue.get("path", "Unknown"),
            line=issue.get("start", {}).get("line"),
            category=["Security"],
            log=json.dumps(issue, indent=2),
            fix_hint=issue.get("extra", {}).get("metadata", {}).get("shortlink", "")
        )
        findings.append(finding)
        issue_id += 1
        
    summary = f"Security scan complete. Analyzed {len(scanned)} file(s). Found {len(findings)} issue(s)."

    return AgentResult(
        agent=AgentType.SECURITY,
        findings=findings,
        summary=summary,
        error=_describe_errors(semgrep_errors) if semgrep_errors else None,
    )