import json
import re
import tempfile
from pathlib import Path

from vtest.core.llm import ask
from vtest.core.models import AgentResult, AgentType, Finding, Severity
from vtest.core.runner import SubprocessError, run_command

def _extract_routes(files: list[Path]) -> list[str]:
    """Naively extracts API routes from Python files (FastAPI/Flask style)."""
    routes = []
    # Looks for @app.get("/route"), @router.post('/route'), etc.
    pattern = re.compile(r'@(?:app|router|server)\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']\)')
    
    for f in files:
        try:
            content = f.read_text(errors="ignore")
            routes.extend(pattern.findall(content))
        except Exception:
            continue
            
    # Default to root if no routes are found to ensure the test still executes
    return list(set(routes)) or ["/"]

def _generate_k6_script(routes: list[str], port: int) -> str:
    """Prompts the LLM to write a targeted k6 load test script."""
    system = (
        "You are an expert performance engineer. Write a complete Javascript k6 load testing script. "
        "Return ONLY raw Javascript code. No markdown fences or explanations."
    )
    
    route_calls = "\n".join([f'    http.get(`http://localhost:{port}{r}`);' for r in routes])
    
    prompt = f"""
Write a k6 script to load test these endpoints:
{routes}

STRICT RULES:
1. Target URL is http://localhost:{port}
2. Use a short ramp-up (e.g., 3s to 10 VUs), hold for 5s, ramp down for 2s.
3. In the default function, make HTTP GET requests to:
{route_calls}
4. Include a sleep(1) at the end of the default function.
5. Return ONLY valid Javascript.
"""
    raw = ask(prompt, system=system)
    # Clean up markdown fences if the LLM hallucinates them
    raw = re.sub(r"^```[a-zA-Z]*\n?", "", raw.strip())
    raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()

async def run(files: list[Path], repo_root: Path, start_id: int = 1, port: int = 3000) -> AgentResult:
    """Executes the k6 load test and evaluates latency constraints."""
    findings = []
    
    routes = _extract_routes(files)
    script_code = _generate_k6_script(routes, port)
    
    if not script_code or "http" not in script_code:
        return AgentResult(agent=AgentType.STRESS, findings=[], summary="Failed to generate k6 script.")
        
    with tempfile.TemporaryDirectory(prefix="vtest_stress_") as tmp:
        tmp_path = Path(tmp)
        script_path = tmp_path / "load_test.js"
        summary_path = tmp_path / "summary.json"
        
        script_path.write_text(script_code)
        
        # k6 must be installed on the host machine
        cmd = ["k6", "run", str(script_path), f"--summary-export={str(summary_path)}"]
        
        try:
            # check=False because k6 returns exit code 99 if thresholds fail
            returncode, output = await run_command(cmd=cmd, cwd=tmp_path, timeout=60, check=False)
        except SubprocessError as e:
            return AgentResult(
                agent=AgentType.STRESS, findings=[], summary="k6 execution failed. Is k6 installed?", error=str(e)
            )
            
        if not summary_path.exists():
            return AgentResult(
                agent=AgentType.STRESS, findings=[], summary="k6 failed to output summary.json", error=output
            )
            
        try:
            summary_data = json.loads(summary_path.read_text())
            metrics = summary_data.get("metrics", {})
            req_duration = metrics.get("http_req_duration", {}).get("values", {})
            
            p95 = req_duration.get("p(95)", 0)
            p90 = req_duration.get("p(90)", 0)
            
            if p95 > 500:
                findings.append(Finding(
                    id=f"{start_id:02d}",
                    title=f"High API Latency (p95: {p95:.2f}ms)",
                    description=f"p95 latency exceeded 500ms threshold (p90: {p90:.2f}ms).",
                    severity=Severity.HIGH,
                    agent=AgentType.STRESS,
                    file_path="k6_load_test",
                    category=["Performance"],
                    log=json.dumps(req_duration, indent=2),
                    fix_hint="Implement caching, optimize database queries, or add pagination to the affected endpoints."
                ))
            else:
                findings.append(Finding(
                    id=f"{start_id:02d}",
                    title=f"Healthy API Latency (p95: {p95:.2f}ms)",
                    description=f"Latency is within acceptable bounds.",
                    severity=Severity.INFO,
                    agent=AgentType.STRESS,
                    file_path="k6_load_test",
                    category=["Performance"],
                    log=json.dumps(req_duration, indent=2),
                    fix_hint=""
                ))
                
        except json.JSONDecodeError:
            return AgentResult(agent=AgentType.STRESS, findings=[], summary="Failed to parse k6 summary JSON.")

    summary = f"Stress test complete. p95 Latency: {p95:.2f}ms." if findings else "Stress test completed with no metrics."
    return AgentResult(agent=AgentType.STRESS, findings=findings, summary=summary)