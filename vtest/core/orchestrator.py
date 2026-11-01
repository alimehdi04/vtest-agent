import asyncio
from pathlib import Path

from vtest.agents.unit_agent import run as run_unit
from vtest.agents.security_agent import DEFAULT_SEMGREP_CONFIG, run as run_security
from vtest.agents.stress_agent import run as run_stress
from vtest.core.runner import PYTEST_IMAGE


async def execute_parallel_agents(
    strategy: dict,
    files: list[Path],
    repo_root: Path,
    port: int = 3000,
    app_cmd: list[str] | None = None,
    sandbox_image: str = PYTEST_IMAGE,
    semgrep_config: str = DEFAULT_SEMGREP_CONFIG,
) -> list:
    """
    Executes all active sub-agents concurrently using asyncio.gather().

    Agents that run repository code (unit, stress) do so only inside the
    container sandbox, using ``sandbox_image`` (the base pytest image or a
    --install-deps image).
    """
    tasks = []

    if strategy.get("run_security"):
        tasks.append(run_security(files=files, repo_root=repo_root, start_id=100, config=semgrep_config))

    if strategy.get("run_unit"):
        tasks.append(run_unit(files=files, repo_root=repo_root, start_id=200, image=sandbox_image))

    # Default is off: stress testing needs an explicit --app-cmd to start the app in the sandbox.
    if strategy.get("run_stress", False):
        tasks.append(run_stress(
            files=files, repo_root=repo_root, start_id=300, port=port,
            app_cmd=app_cmd, app_image=sandbox_image,
        ))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results
