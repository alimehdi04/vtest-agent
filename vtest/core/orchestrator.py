import asyncio
from pathlib import Path

from vtest.agents.unit_agent import run as run_unit
from vtest.agents.security_agent import run as run_security
from vtest.agents.stress_agent import run as run_stress # <-- Add import

async def execute_parallel_agents(strategy: dict, files: list[Path], repo_root: Path, port: int = 3000) -> list:
    """
    Executes all active sub-agents concurrently using asyncio.gather().
    """
    tasks = []
    
    if strategy.get("run_security"):
        tasks.append(run_security(files=files, repo_root=repo_root, start_id=100))
        
    if strategy.get("run_unit"):
        tasks.append(run_unit(files=files, repo_root=repo_root, start_id=200))
        
    if strategy.get("run_stress", True): # Assuming true for MVP testing
        tasks.append(run_stress(files=files, repo_root=repo_root, start_id=300, port=port)) # <-- Add task
        
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results