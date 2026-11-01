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

import json
import re
from pathlib import Path

from vtest.core.models import AgentResult, AgentType, Finding, Severity
from vtest.core.runner import SubprocessError, run_tool

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


def build_semgrep_cmd(config: str) -> list[str]:
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
    ]


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
        cmd = build_semgrep_cmd(config)
    except SemgrepConfigError as e:
        return AgentResult(
            agent=AgentType.SECURITY, findings=[], summary="Security scan not run: invalid Semgrep config.", error=str(e)
        )

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

    semgrep_findings = report.get("results", [])
    
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
        
    summary = f"Security scan complete. Found {len(findings)} issue(s)."
    
    return AgentResult(
        agent=AgentType.SECURITY,
        findings=findings,
        summary=summary,
        error=None
    )