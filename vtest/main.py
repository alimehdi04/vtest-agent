import asyncio
import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from vtest.core.ingestion import scan_codebase
from vtest.agents.security_agent import run as run_security_agent
from vtest.agents.stress_agent import run as run_stress_agent
from vtest.agents.security_agent import DEFAULT_SEMGREP_CONFIG
from vtest.core.llm import allow_uploads
from vtest.orchestrator.router import get_testing_strategy, local_strategy
from vtest.reporting.synthesizer import OutputPathError, generate_reports
from vtest.core.orchestrator import execute_parallel_agents
from vtest.core.runner import (
    K6_IMAGE,
    PYTEST_IMAGE,
    SandboxUnavailable,
    SubprocessError,
    build_dependency_image,
    get_runtime,
    image_exists,
    reap_stale_sandboxes,
)
from vtest.sandbox.images import build_sandbox_images

# Initialize Typer app and Rich console
app = typer.Typer(
    name="vtest",
    help="AI-powered code health agent: Unit, Security, and Stress testing.",
    add_completion=False
)
console = Console()

MAX_REQUIREMENTS_BYTES = 256 * 1024
EXCLUDED_PARTS = ["venv", ".venv", ".git", "__pycache__", "node_modules", "output"]


# ── Sandbox preflight ───────────────────────────────────────────────────────

@dataclass
class SandboxSetup:
    ok: bool
    image: str = PYTEST_IMAGE
    k6_ok: bool = False
    messages: list[str] = field(default_factory=list)     # Rich-markup-safe lines


async def _prepare_sandbox(repo_root: Path, install_deps: bool, need_k6: bool) -> SandboxSetup:
    """
    Fail-closed preflight for every agent that executes repository code:
      1. detect a runtime that can enforce limits (Podman first),
      2. remove containers left behind by earlier crashed runs,
      3. check the sandbox images exist,
      4. optionally (--install-deps) build the repo's wheel-only dependency image.
    """
    setup = SandboxSetup(ok=False)
    try:
        rt = await get_runtime()
    except SandboxUnavailable as e:
        setup.messages.append(f"[red]✗ Sandbox unavailable: {escape(str(e))}[/red]")
        return setup

    setup.messages.append(
        f"[green]✓[/green] Sandbox runtime: {rt.kind} ({'rootless' if rt.rootless else '[yellow]rootful[/yellow]'})"
    )
    for w in rt.warnings:
        setup.messages.append(f"[yellow]⚠ {escape(w)}[/yellow]")

    reaped = await reap_stale_sandboxes(rt)
    if reaped:
        setup.messages.append(f"[yellow]⚠[/yellow] Removed {reaped} stale sandbox container(s) from a previous run")

    if not await image_exists(PYTEST_IMAGE, rt):
        setup.messages.append(
            f"[red]✗ Sandbox image {PYTEST_IMAGE} not found. Run `vtest sandbox-build` first.[/red]"
        )
        return setup
    setup.ok = True

    if need_k6:
        setup.k6_ok = await image_exists(K6_IMAGE, rt)
        if not setup.k6_ok:
            setup.messages.append(
                f"[yellow]⚠ Sandbox image {K6_IMAGE} not found; stress test disabled. Run `vtest sandbox-build`.[/yellow]"
            )

    if install_deps:
        req = repo_root / "requirements.txt"
        if req.is_symlink() or not req.is_file():
            setup.messages.append("[yellow]⚠ --install-deps: no regular requirements.txt at the repo root; using base image[/yellow]")
        elif req.stat().st_size > MAX_REQUIREMENTS_BYTES:
            setup.messages.append("[yellow]⚠ --install-deps: requirements.txt is too large; using base image[/yellow]")
        else:
            try:
                deps = await build_dependency_image(req.read_text(errors="ignore"), base_image=PYTEST_IMAGE, runtime=rt)
            except SubprocessError as e:
                setup.messages.append(
                    f"[yellow]⚠ --install-deps: dependency image build failed; using base image.[/yellow]\n"
                    f"   [dim]{escape(str(e)[-800:])}[/dim]"
                )
            else:
                setup.image = deps.image
                verb = "Built" if deps.built else "Reusing"
                setup.messages.append(
                    f"[green]✓[/green] {verb} dependency image {escape(deps.image)} ({len(deps.accepted)} wheel-only requirement(s))"
                )
                for line in deps.rejected[:10]:
                    setup.messages.append(f"   [yellow]ignored unsafe requirement:[/yellow] {escape(line[:120])}")
    return setup


def _parse_app_cmd(app_cmd: Optional[str]) -> Optional[list[str]]:
    if not app_cmd:
        return None
    try:
        parts = shlex.split(app_cmd)
    except ValueError as e:
        raise typer.BadParameter(f"Could not parse --app-cmd: {e}")
    return parts or None


def _collect_python_files(repo_root: Path) -> list[Path]:
    """Regular .py files that are really inside repo_root (M2: no symlinks, nothing resolving outside)."""
    files = []
    for p in repo_root.rglob("*.py"):
        if p.is_symlink() or not p.is_file():
            continue
        rel_parts = p.relative_to(repo_root).parts
        if any(part in EXCLUDED_PARTS for part in rel_parts):
            continue
        if not p.resolve().is_relative_to(repo_root):
            continue
        files.append(p)
    return files


# ── Commands ────────────────────────────────────────────────────────────────

@app.command()
def analyze(
    path: str = typer.Argument(".", help="Path to the local codebase to analyze"),
    port: int = typer.Option(3000, min=1, max=65535, help="Port the app listens on inside the sandbox (stress test)"),
    app_cmd: Optional[str] = typer.Option(
        None, "--app-cmd",
        help="Command that starts the app inside the sandbox, e.g. \"python3 -m uvicorn main:app --port 3000\". "
             "Required for the stress test.",
    ),
    install_deps: bool = typer.Option(
        False, "--install-deps",
        help="Build a sandbox image with the repo's requirements.txt (wheels only; no setup scripts run).",
    ),
    allow_llm_upload: bool = typer.Option(
        False, "--allow-llm-upload",
        help="Consent to sending code skeletons (signatures + docstrings, secrets redacted) and repo "
             "metadata to the Groq API. Without it, no data is sent and LLM unit tests are skipped.",
    ),
    semgrep_config: str = typer.Option(
        DEFAULT_SEMGREP_CONFIG, "--semgrep-config",
        help="Semgrep ruleset: a registry pack (p/<name>) or a local rules file/directory for offline scans.",
    ),
):
    """
    Run the full vtest suite (Unit, Security, Stress) on a local directory.
    """
    app_cmd_list = _parse_app_cmd(app_cmd)
    allow_uploads(allow_llm_upload)                    # M5: the gate every LLM call checks

    with console.status(f"[bold green]Scanning codebase at {escape(path)}...[/bold green]", spinner="dots"):

        # 1. Ingestion Layer
        context = scan_codebase(path)
        console.log(f"[green]✓[/green] Ingested {context['total_files']} files")
        console.log(f"[blue]ℹ[/blue] Detected: [bold]{context['primary_language']}[/bold] / [bold]{context['framework']}[/bold]")

        # 2. Orchestrator Routing (L4: strict schema; M5: no Groq call without consent)
        try:
            if allow_llm_upload:
                validated = get_testing_strategy(context)
                console.log("[green]✓[/green] Orchestrator determined testing strategy:")
            else:
                validated = local_strategy(context, app_cmd_given=bool(app_cmd_list))
                console.log("[yellow]⚠[/yellow] LLM upload not allowed: nothing will be sent to Groq (local strategy)")
            console.print(f"   [dim]Reasoning: {escape(validated.reasoning)}[/dim]")
        except Exception as e:
            console.log(f"[red]✗ Orchestrator failed: {escape(str(e))}[/red]")
            raise typer.Exit(code=1)
        strategy = validated.model_dump()

        repo_root = Path(path).resolve()

        # 3. Sandbox preflight (fail closed for agents that execute repo code)
        wants_stress = bool(strategy.get("run_stress"))
        if wants_stress and not app_cmd_list:
            console.log("[yellow]⚠[/yellow] Stress test skipped: pass --app-cmd to start the app inside the sandbox")
            strategy["run_stress"] = False
            wants_stress = False

        if strategy.get("run_unit") or wants_stress:
            setup = asyncio.run(_prepare_sandbox(repo_root, install_deps, need_k6=wants_stress))
            for msg in setup.messages:
                console.log(msg)
            if not setup.ok:
                console.log("[red]✗ Unit and stress agents disabled: they never run repository code outside the sandbox.[/red]")
                strategy["run_unit"] = False
                strategy["run_stress"] = False
            elif wants_stress and not setup.k6_ok:
                strategy["run_stress"] = False
            sandbox_image = setup.image
        else:
            sandbox_image = PYTEST_IMAGE

        # 4. Execute Sub-Agents
        source_files = _collect_python_files(repo_root)

        console.log("[yellow]⚡[/yellow] Dispatching parallel sub-agents...")
        agent_results = asyncio.run(execute_parallel_agents(
            strategy, source_files, repo_root, port,
            app_cmd=app_cmd_list, sandbox_image=sandbox_image, semgrep_config=semgrep_config,
        ))

        all_findings = []
        for result in agent_results:
            if isinstance(result, Exception):
                console.print(f"   [red]Agent Crash: {escape(str(result))}[/red]")
                continue

            console.print(f"   [dim]{escape(result.summary)}[/dim]")
            if result.error:
                console.print(f"   [red]Errors: {escape(result.error)}[/red]")

            for finding in result.findings:
                all_findings.append({
                    "id": finding.id,
                    "severity": finding.severity.value,
                    "issue": finding.title,
                    "file_line": f"{finding.file_path}:{finding.line or 'N/A'}",
                    "agent": finding.agent.value,
                    "raw_log": finding.log
                })

        console.log("[green]✓[/green] Parallel sub-agents completed")

        # 5. Report Generation (only ever inside <repo_root>/output, never through a symlink)
        try:
            audit_file, brief_file = generate_reports(context, all_findings, repo_root)
            console.log("[green]✓[/green] Reports synthesized")
        except OutputPathError as e:
            audit_file = brief_file = None
            console.log(f"[red]✗ Reports not written: {escape(str(e))}[/red]")

    # 6. Terminal Dashboard
    if all_findings:
        console.print("\n[bold]Diagnostic Findings[/bold]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=6)
        table.add_column("Severity")
        table.add_column("Agent", justify="center")
        table.add_column("File:Line")
        table.add_column("Issue")

        for f in all_findings:
            sev = f['severity']
            # Color-code based on severity level
            color = "red" if sev in ["Critical", "High"] else "yellow" if sev == "Medium" else "blue" if sev == "Low" else "white"

            table.add_row(
                escape(f['id']),
                f"[{color}]{sev}[/{color}]",
                f['agent'],
                escape(f['file_line']),
                escape(f['issue'])
            )
        console.print(table)
    else:
        console.print("\n[bold green]✓ No issues found across all agents![/bold green]")

    if audit_file is None:
        console.print("\n[bold red]Audit finished, but no report files were written (see error above).[/bold red]")
        raise typer.Exit(code=1)

    console.print("\n[bold blue]Audit complete! Check your output files:[/bold blue]")
    console.print(f" 📄 {escape(audit_file)}")
    console.print(f" 🤖 {escape(brief_file)}\n")


@app.command()
def security(
    path: str = typer.Argument(".", help="Path to the local codebase"),
    semgrep_config: str = typer.Option(
        DEFAULT_SEMGREP_CONFIG, "--semgrep-config",
        help="Semgrep ruleset: a registry pack (p/<name>) or a local rules file/directory for offline scans.",
    ),
):
    """
    Run ONLY the security sub-agent (Semgrep static analysis).
    """
    with console.status(f"[bold yellow]Running standalone security scan on {escape(path)}...[/bold yellow]", spinner="bouncingBar"):
        repo_root = Path(path).resolve()
        source_files = _collect_python_files(repo_root)
        result = asyncio.run(run_security_agent(
            files=source_files, repo_root=repo_root, start_id=100, config=semgrep_config,
        ))

    if result.error:
        console.print(f"[red]{escape(result.summary)} {escape(result.error)}[/red]")
        return
    if not result.findings:
        console.print("[bold green]✓ No security issues found![/bold green]")
        return

    console.print(f"\n[bold red]Found {len(result.findings)} security issues:[/bold red]")

    for f in result.findings:
        console.print(f"[{f.severity.value}] {escape(f.file_path)}:{f.line} - {escape(f.title)}")


@app.command()
def stress(
    path: str = typer.Argument(".", help="Path to the local codebase"),
    app_cmd: str = typer.Option(..., "--app-cmd", help="Command that starts the app inside the sandbox"),
    port: int = typer.Option(3000, min=1, max=65535, help="Port the app listens on inside the sandbox"),
    install_deps: bool = typer.Option(False, "--install-deps", help="Build a wheel-only dependency image first"),
):
    """
    Run ONLY the stress test sub-agent (k6), with the app and k6 both sandboxed.
    """
    app_cmd_list = _parse_app_cmd(app_cmd)
    repo_root = Path(path).resolve()

    setup = asyncio.run(_prepare_sandbox(repo_root, install_deps, need_k6=True))
    for msg in setup.messages:
        console.print(msg)
    if not setup.ok or not setup.k6_ok:
        console.print("[red]✗ Stress test not run: the sandbox is not ready.[/red]")
        raise typer.Exit(code=1)

    with console.status(f"[bold yellow]Running sandboxed stress test on port {port}...[/bold yellow]", spinner="bouncingBar"):
        result = asyncio.run(run_stress_agent(
            files=_collect_python_files(repo_root), repo_root=repo_root, start_id=300,
            port=port, app_cmd=app_cmd_list, app_image=setup.image,
        ))

    console.print(f"[dim]{escape(result.summary)}[/dim]")
    if result.error:
        console.print(f"[red]Errors: {escape(result.error)}[/red]")
    for f in result.findings:
        console.print(f"[{f.severity.value}] {escape(f.title)}")


@app.command("sandbox-build")
def sandbox_build():
    """
    Build the sandbox images (pytest and k6) from vtest's pinned Containerfiles.
    """
    async def _build():
        rt = await get_runtime()
        console.print(f"Using {rt.kind} ({'rootless' if rt.rootless else 'rootful'})")
        return await build_sandbox_images(rt)

    try:
        with console.status("[bold]Building sandbox images...[/bold]", spinner="dots"):
            builds = asyncio.run(_build())
    except SandboxUnavailable as e:
        console.print(f"[red]✗ {escape(str(e))}[/red]")
        raise typer.Exit(code=1)

    failed = False
    for b in builds:
        if b.ok:
            console.print(f"[green]✓[/green] {b.image}")
        else:
            failed = True
            console.print(f"[red]✗ {b.image}[/red]\n[dim]{escape(b.log[-2000:])}[/dim]")
    if failed:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
