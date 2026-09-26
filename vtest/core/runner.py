import asyncio
from pathlib import Path

class SubprocessError(Exception):
    """Raised when a subprocess fails or times out."""
    pass

async def run_command(cmd: list[str], cwd: Path, timeout: int = 60, check: bool = True) -> tuple[int, str]:
    """
    Executes a shell command asynchronously to prevent blocking the main thread.
    Captures stdout and stderr into a single stream, enforcing a strict timeout.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        stdout_bytes, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        output = stdout_bytes.decode('utf-8', errors='replace')
        
        if check and proc.returncode != 0:
            raise SubprocessError(output)
            
        return proc.returncode, output
        
    except asyncio.TimeoutError:
        proc.kill()
        raise SubprocessError(f"Command timed out after {timeout} seconds:\n{' '.join(cmd)}")
    except Exception as e:
        if isinstance(e, SubprocessError):
            raise
        raise SubprocessError(f"System execution failed: {e}")