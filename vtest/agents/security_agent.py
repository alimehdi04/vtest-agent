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
import asyncio
from pathlib import Path

from vtest.core.models import AgentResult, AgentType, Finding, Severity
from vtest.core.runner import SubprocessError, run_command

async def run(files: list[Path], repo_root: Path, start_id: int = 1) -> AgentResult:
    """
    Runs Semgrep locally using OWASP rules and maps findings to Pydantic models.
    """
    findings = []
    
    cmd = [
        "semgrep",
        "scan",
        "--config", "auto",
        "--exclude", "venv",
        "--exclude", ".venv",
        "--exclude", "node_modules",
        "--json",
        "--quiet"
    ]
    
    try:
        # Semgrep returns exit code 0 if perfectly clean
        returncode, output = await run_command(cmd=cmd, cwd=repo_root, timeout=300) # Increased to 5 minutes
    
    except SubprocessError as e:
        # Semgrep returns exit code 1 if it finds vulnerabilities, triggering this exception.
        # The JSON output is contained inside the error message.
        output = str(e)
        if not output.strip().startswith("{"):
            return AgentResult(
                agent=AgentType.SECURITY,
                findings=[],
                summary="Security scan failed to execute.",
                error=f"Semgrep execution error: {e}"
            )
            
    try:
        report = json.loads(output)
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