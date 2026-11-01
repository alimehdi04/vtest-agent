"""
Stress Agent
============
H2 / Decision A:
  * No LLM-generated JavaScript. k6 always runs the fixed template in
    vtest/sandbox/k6_template.js. Discovered routes are validated on the host
    and passed to it as JSON data in an environment variable.
  * The target app runs in a --network=none container (SandboxedService).
    k6 runs in a second sandbox that joins the app's network namespace, so the
    only network either can reach is the shared loopback interface.
"""

import json
import re
from pathlib import Path

from vtest.core.models import AgentResult, AgentType, Finding, Severity
from vtest.core.runner import (
    K6_IMAGE,
    PYTEST_IMAGE,
    SandboxedService,
    SandboxPolicy,
    SandboxUnavailable,
    SubprocessError,
    make_tree_tar,
    run_sandboxed,
)
from vtest.sandbox import K6_TEMPLATE_PATH

MAX_ROUTES = 50
MAX_ROUTE_LEN = 200
LATENCY_P95_THRESHOLD_MS = 500
ERROR_RATE_THRESHOLD = 0.05
K6_TIMEOUT = 120
APP_MAX_LIFETIME = 240
APP_START_TIMEOUT = 30

_ROUTE_DECORATOR_RE = re.compile(
    r'@(?:app|router|server)\.(?:get|post|put|delete|patch)\(["\']([^"\']+)["\']\)'
)
_PATH_PARAM_RE = re.compile(r"\{[^{}/]*\}|<[^<>/]*>|:[A-Za-z_][A-Za-z0-9_]*")
_SAFE_ROUTE_RE = re.compile(r"^/[A-Za-z0-9/_\-.~]*$")   # mirrored in k6_template.js


def _extract_routes(files: list[Path]) -> list[str]:
    """Naively extract API route strings from Python files (FastAPI/Flask style). Untrusted."""
    routes: list[str] = []
    for f in files:
        if f.is_symlink():
            continue
        try:
            routes.extend(_ROUTE_DECORATOR_RE.findall(f.read_text(errors="ignore")))
        except OSError:
            continue
    return routes


def _normalise_routes(raw_routes: list[str]) -> tuple[list[str], list[str]]:
    """
    Turn raw (repo-controlled) route strings into safe concrete paths.
    Path parameters ({id}, <int:id>, :id) become "1". Anything outside a strict
    character set is rejected, so no template-literal, quote or URL syntax ever
    reaches k6. Returns (accepted, rejected).
    """
    accepted: set[str] = set()
    rejected: list[str] = []
    for raw in raw_routes:
        cand = _PATH_PARAM_RE.sub("1", raw.strip())
        if not cand.startswith("/"):
            cand = "/" + cand
        if len(cand) <= MAX_ROUTE_LEN and ".." not in cand and _SAFE_ROUTE_RE.fullmatch(cand):
            accepted.add(cand)
        else:
            rejected.append(raw[:80])
    routes = sorted(accepted)[:MAX_ROUTES]
    return (routes or ["/"]), rejected


def _parse_summary(stdout: str) -> dict | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Be tolerant of stray lines before the summary JSON.
        start = text.find("{")
        if start < 0:
            return None
        try:
            data = json.loads(text[start:])
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def _metric_values(metrics: dict, name: str) -> dict:
    metric = metrics.get(f"{name}{{phase:load}}") or metrics.get(name) or {}
    values = metric.get("values", metric) if isinstance(metric, dict) else {}
    return values if isinstance(values, dict) else {}


def _num(value) -> float:
    return float(value) if isinstance(value, (int, float)) else 0.0


def _result(summary: str, findings: list[Finding] | None = None, error: str | None = None) -> AgentResult:
    return AgentResult(agent=AgentType.STRESS, findings=findings or [], summary=summary, error=error)


async def run(
    files: list[Path],
    repo_root: Path,
    start_id: int = 1,
    port: int = 3000,
    app_cmd: list[str] | None = None,
    app_image: str = PYTEST_IMAGE,
) -> AgentResult:
    """Start the app in a sandbox, load-test it with the fixed k6 template, and report latency."""
    if not app_cmd:
        return _result(
            "Stress test skipped: no --app-cmd given. The app must run inside the sandbox "
            "(e.g. --app-cmd \"python3 -m uvicorn main:app --host 127.0.0.1 --port 3000\")."
        )
    if not (1 <= int(port) <= 65535):
        return _result("Stress test skipped: invalid port.", error=f"port {port!r} out of range")

    routes, rejected = _normalise_routes(_extract_routes(files))

    try:
        repo_tar = make_tree_tar(repo_root)
    except ValueError as e:
        return _result("Stress test skipped: repository too large for the sandbox.", error=str(e))

    script = K6_TEMPLATE_PATH.read_bytes()

    app_policy = SandboxPolicy(
        image=app_image,
        network="none",
        memory="1g",
        cpus="2.0",
        pids_limit=256,
        workdir_size="256m",
    )

    try:
        async with SandboxedService(
            app_policy,
            ["app", "--", *app_cmd],
            stdin_data=repo_tar,
            max_lifetime=APP_MAX_LIFETIME,
        ) as app:
            await app.wait_running(timeout=APP_START_TIMEOUT)
            k6_policy = SandboxPolicy(
                image=K6_IMAGE,
                uid=12345,
                network=app.network_ref,
                memory="512m",
                pids_limit=128,
                env=(("VTEST_ROUTES", json.dumps(routes)), ("VTEST_PORT", str(int(port)))),
            )
            res = await run_sandboxed(k6_policy, ["run", "--quiet", "-"], stdin_data=script, timeout=K6_TIMEOUT)
            app_log = app.output()
    except SandboxUnavailable:
        raise                                            # fail closed
    except SubprocessError as e:
        return _result("Stress test failed to run in the sandbox.", error=str(e)[:2000])

    summary_data = _parse_summary(res.stdout)
    if summary_data is None or "metrics" not in summary_data:
        return _result(
            "Stress test produced no k6 summary (did the app start and listen on the given port?).",
            error=f"k6 exit {res.returncode}.\n--- k6 stderr (tail) ---\n{res.stderr[-1500:]}"
                  f"\n--- app output (tail) ---\n{app_log[-1500:]}",
        )

    metrics = summary_data.get("metrics", {})
    duration = _metric_values(metrics, "http_req_duration")
    failed = _metric_values(metrics, "http_req_failed")
    p95, p90 = _num(duration.get("p(95)")), _num(duration.get("p(90)"))
    fail_rate = _num(failed.get("rate"))
    log_blob = json.dumps({"routes": routes, "http_req_duration": duration, "http_req_failed": failed}, indent=2)

    findings: list[Finding] = []
    next_id = start_id

    if p95 > LATENCY_P95_THRESHOLD_MS:
        findings.append(Finding(
            id=f"{next_id:02d}",
            title=f"High API Latency (p95: {p95:.2f}ms)",
            description=f"p95 latency exceeded {LATENCY_P95_THRESHOLD_MS}ms threshold (p90: {p90:.2f}ms).",
            severity=Severity.HIGH,
            agent=AgentType.STRESS,
            file_path="k6_load_test",
            category=["Performance"],
            log=log_blob,
            fix_hint="Implement caching, optimize database queries, or add pagination to the affected endpoints.",
        ))
    else:
        findings.append(Finding(
            id=f"{next_id:02d}",
            title=f"Healthy API Latency (p95: {p95:.2f}ms)",
            description="Latency is within acceptable bounds.",
            severity=Severity.INFO,
            agent=AgentType.STRESS,
            file_path="k6_load_test",
            category=["Performance"],
            log=log_blob,
            fix_hint="",
        ))
    next_id += 1

    if fail_rate > ERROR_RATE_THRESHOLD:
        findings.append(Finding(
            id=f"{next_id:02d}",
            title=f"High request failure rate under load ({fail_rate:.1%})",
            description="More than 5% of load-test requests failed (non-2xx/3xx status, timeout or connection error).",
            severity=Severity.HIGH,
            agent=AgentType.STRESS,
            file_path="k6_load_test",
            category=["Performance"],
            log=log_blob,
            fix_hint="Check the failing routes for errors under concurrent load (status codes, timeouts, resource limits).",
        ))

    summary = f"Stress test complete. p95 latency: {p95:.2f}ms, failure rate: {fail_rate:.1%}, {len(routes)} route(s)."
    if rejected:
        summary += f" {len(rejected)} unsafe route string(s) ignored."
    return _result(summary, findings)
