import typer
from rich.console import Console
from rich.table import Table
import time
import asyncio
from pathlib import Path

from vtest.core.ingestion import scan_codebase
from vtest.agents.security_agent import run as run_security_agent
from vtest.orchestrator.router import get_testing_strategy
from vtest.reporting.synthesizer import generate_reports 
from vtest.agents.unit_agent import run as run_unit_agent
from vtest.core.orchestrator import execute_parallel_agents

# Initialize Typer app and Rich console
app = typer.Typer(
    name="vtest",
    help="AI-powered code health agent: Unit, Security, and Stress testing.",
    add_completion=False
)
console = Console()

@app.command()
def analyze(
    path: str = typer.Argument(".", help="Path to the local codebase to analyze"),
    port: int = typer.Option(3000, help="Local port where the app is running for stress tests")
):
    """
    Run the full vtest suite (Unit, Security, Stress) on a local directory.
    """
    with console.status(f"[bold green]Scanning codebase at {path}...[/bold green]", spinner="dots"):
        
        # 1. Ingestion Layer
        context = scan_codebase(path)
        console.log(f"[green]✓[/green] Ingested {context['total_files']} files")
        console.log(f"[blue]ℹ[/blue] Detected: [bold]{context['primary_language']}[/bold] / [bold]{context['framework']}[/bold]")
        
        # 2. Orchestrator Routing
        try:
            strategy = get_testing_strategy(context)
            console.log("[green]✓[/green] Orchestrator determined testing strategy:")
            console.print(f"   [dim]Reasoning: {strategy['reasoning']}[/dim]")
        except Exception as e:
            console.log(f"[red]✗ Orchestrator failed: {e}[/red]")
            return

        # 3. Execute Sub-Agents
        repo_root = Path(path).resolve()
        source_files = [
            p for p in repo_root.rglob("*.py") 
            if p.is_file() and not any(part in ["venv", ".git", "__pycache__", "node_modules", "output"] for part in p.parts)
        ]

        # CHANGE IMMEDIATELY (changed)
        # strategy["run_stress"] = True
        console.log("[yellow]⚡[/yellow] Dispatching parallel sub-agents...")
        agent_results = asyncio.run(execute_parallel_agents(strategy, source_files, repo_root, port))
        
        all_findings = []
        for result in agent_results:
            if isinstance(result, Exception):
                console.print(f"   [red]Agent Crash: {result}[/red]")
                continue
                
            console.print(f"   [dim]{result.summary}[/dim]")
            if result.error:
                console.print(f"   [red]Errors: {result.error}[/red]")
                
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
        
        # 4. Report Generation
        audit_file, brief_file = generate_reports(context, all_findings)
        console.log("[green]✓[/green] Reports synthesized")
        
    # 5. Terminal Dashboard
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
                f['id'],
                f"[{color}]{sev}[/{color}]",
                f['agent'],
                f['file_line'],
                f['issue']
            )
        console.print(table)
    else:
        console.print("\n[bold green]✓ No issues found across all agents![/bold green]")
        
    console.print("\n[bold blue]Audit complete! Check your output files:[/bold blue]")
    console.print(f" 📄 {audit_file}")
    console.print(f" 🤖 {brief_file}\n")

@app.command()
def security(
    path: str = typer.Argument(".", help="Path to the local codebase")
):
    """
    Run ONLY the security sub-agent (Semgrep static analysis).
    """
    with console.status(f"[bold yellow]Running standalone security scan on {path}...[/bold yellow]", spinner="bouncingBar"):
        repo_root = Path(path).resolve()
        source_files = [
            p for p in repo_root.rglob("*.py") 
            if p.is_file() and not any(part in ["venv", ".git", "__pycache__", "node_modules", "output"] for part in p.parts)
        ]
        
        # Execute the new async agent
        result = asyncio.run(run_security_agent(files=source_files, repo_root=repo_root, start_id=100))
        
    if not result.findings:
        console.print("[bold green]✓ No security issues found![/bold green]")
        return
        
    console.print(f"\n[bold red]Found {len(result.findings)} security issues:[/bold red]")
    
    for f in result.findings:
        console.print(f"[{f.severity.value}] {f.file_path}:{f.line} - {f.title}")


@app.command()
def stress(
    port: int = typer.Option(3000, help="Local port where the app is running")
):
    """
    Run ONLY the stress test sub-agent (k6).
    """
    console.print(f"[yellow]Running standalone stress test against localhost:{port}...[/yellow]")

if __name__ == "__main__":
    app()