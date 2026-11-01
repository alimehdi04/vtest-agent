"""
Process execution for vtest.

Two kinds of execution live here, and they must not be mixed up:

* ``run_command()`` -- host-side execution of *trusted* tools only (Semgrep,
  the container CLI). Hardened: allow-listed environment, own process group,
  process-group kill on timeout, 1 MB output cap.

* ``run_sandboxed()`` / ``SandboxedService`` -- every execution of repository
  code or LLM-derived code (pytest, k6, the target app). Runs inside a
  rootless Podman (default) or Docker container with no network, no
  capabilities, an unprivileged user, a read-only root filesystem and
  PID/memory/CPU limits. Fails closed: if no runtime is available, or it
  cannot enforce the limits, ``SandboxUnavailable`` is raised and nothing runs
  on the host.

Files go into a sandbox as an in-memory tar on stdin and results come back
on stdout/stderr, so no host path is ever bind-mounted.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import os
import re
import shutil
import signal
import stat
import tarfile
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

# ── Limits & constants ──────────────────────────────────────────────────────

MAX_OUTPUT_BYTES = 1024 * 1024          # strict cap on captured output (stdout+stderr combined)
_READ_CHUNK = 64 * 1024
_KILL_GRACE_SECONDS = 5

SANDBOX_LABEL_KEY = "vtest.sandbox"
SANDBOX_LABEL = f"{SANDBOX_LABEL_KEY}=1"

# Image names. Built locally and never pulled (``--pull=never``).
PYTEST_IMAGE = "localhost/vtest-pytest:1"
K6_IMAGE = "localhost/vtest-k6:1"
DEPS_IMAGE_REPO = "localhost/vtest-deps"

# H3: the ONLY host environment variables any child process ever receives.
# GROQ_API_KEY, cloud credentials, tokens, PYTEST_ADDOPTS, PYTHONPATH etc. are dropped.
_ENV_PASSTHROUGH = ("PATH", "LANG")
_ENV_FIXED = {"PYTHONDONTWRITEBYTECODE": "1"}


# ── Errors ──────────────────────────────────────────────────────────────────

class SubprocessError(Exception):
    """Raised when a subprocess fails, cannot start, or times out."""


class SubprocessTimeout(SubprocessError):
    """Raised when a subprocess exceeds its timeout (its process group was killed)."""


class SandboxUnavailable(SubprocessError):
    """No usable sandbox. Untrusted code must NOT be run on the host instead."""


class SandboxExecError(SubprocessError):
    """The container runtime failed to run the container (not a test result)."""


# ── Environment ─────────────────────────────────────────────────────────────

def minimal_env() -> dict[str, str]:
    """Allow-listed environment for every child process (H3)."""
    env = {k: os.environ[k] for k in _ENV_PASSTHROUGH if k in os.environ}
    env.setdefault("PATH", os.defpath)
    env.update(_ENV_FIXED)
    return env


# ── Low-level hardened exec ─────────────────────────────────────────────────

@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str
    truncated: bool

    @property
    def output(self) -> str:
        """stdout and stderr joined (stderr is empty when the streams were merged)."""
        return self.stdout + self.stderr


class _OutputBudget:
    """One byte budget shared by stdout and stderr, so the total is capped."""

    def __init__(self, limit: int) -> None:
        self.remaining = max(limit, 0)
        self.truncated = False

    def take(self, chunk: bytes) -> bytes:
        if len(chunk) > self.remaining:
            self.truncated = True
        kept = chunk[: self.remaining]
        self.remaining -= len(kept)
        return kept


async def _drain(stream: asyncio.StreamReader | None, budget: _OutputBudget, sink: bytearray) -> None:
    """Read a pipe to EOF. Bytes over the budget are discarded, but the pipe
    is still drained so the child can never block on a full pipe."""
    if stream is None:
        return
    while chunk := await stream.read(_READ_CHUNK):
        sink += budget.take(chunk)


def _kill_group(pid: int) -> None:
    """M4: SIGKILL the whole process group, not just the direct child."""
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _decode(data: bytearray) -> str:
    return bytes(data).decode("utf-8", errors="replace")


async def _exec(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float = 60,
    stdin_data: bytes | None = None,
    merge_stderr: bool = False,
    max_output: int = MAX_OUTPUT_BYTES,
) -> ExecResult:
    if not argv:
        raise SubprocessError("empty command")

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=minimal_env(),                   # H3: never inherit os.environ
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT if merge_stderr else asyncio.subprocess.PIPE,
            start_new_session=True,              # M4: own session -> own process group
        )
    except OSError as e:
        raise SubprocessError(f"System execution failed: {Path(argv[0]).name}: {e}") from e

    budget = _OutputBudget(max_output)
    out, err = bytearray(), bytearray()

    async def feed() -> None:
        if stdin_data is None or proc.stdin is None:
            return
        try:
            proc.stdin.write(stdin_data)
            await proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            proc.stdin.close()

    try:
        await asyncio.wait_for(
            asyncio.gather(
                feed(),
                _drain(proc.stdout, budget, out),
                _drain(proc.stderr, budget, err),
                proc.wait(),
            ),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        _kill_group(proc.pid)
        try:
            await asyncio.wait_for(proc.wait(), timeout=_KILL_GRACE_SECONDS)
        except asyncio.TimeoutError:
            pass
        raise SubprocessTimeout(
            f"Command timed out after {timeout} seconds: {Path(argv[0]).name}"
        ) from None
    finally:
        # Covers cancellation and unexpected errors: never leave the group running.
        if proc.returncode is None:
            _kill_group(proc.pid)

    if budget.truncated:
        notice = f"\n[vtest: output truncated at {max_output} bytes]\n".encode()
        (out if merge_stderr else err).extend(notice)

    return ExecResult(
        returncode=proc.returncode if proc.returncode is not None else -signal.SIGKILL,
        stdout=_decode(out),
        stderr=_decode(err),
        truncated=budget.truncated,
    )


async def run_command(
    cmd: list[str],
    cwd: Path,
    timeout: int = 60,
    check: bool = True,
    max_output: int = MAX_OUTPUT_BYTES,
) -> tuple[int, str]:
    """
    Run a TRUSTED host tool (Semgrep, the container CLI). Never use this for
    repository code or LLM output; use ``run_sandboxed()`` for those.

    stdout and stderr are merged and capped at ``max_output`` bytes. The
    signature and return value match the previous version, so existing callers
    keep working.
    """
    res = await _exec(list(cmd), cwd=cwd, timeout=timeout, merge_stderr=True, max_output=max_output)
    if check and res.returncode != 0:
        raise SubprocessError(res.output)
    return res.returncode, res.output


async def run_tool(
    cmd: list[str],
    cwd: Path,
    timeout: int = 60,
    max_output: int = MAX_OUTPUT_BYTES,
) -> ExecResult:
    """
    Like ``run_command()`` (trusted host tools only), but keeps stdout and
    stderr separate and returns the full ``ExecResult`` without raising on a
    non-zero exit code. Use it when stdout is machine-readable (e.g. Semgrep JSON).
    """
    return await _exec(list(cmd), cwd=cwd, timeout=timeout, merge_stderr=False, max_output=max_output)


# ── Container runtime detection & preflight ─────────────────────────────────

@dataclass(frozen=True)
class ContainerRuntime:
    path: str
    kind: str                 # "podman" | "docker"
    rootless: bool
    warnings: tuple[str, ...] = ()


_runtime_cache: ContainerRuntime | None = None

_REQUIRED_CGROUP_CONTROLLERS = {"cpu", "memory", "pids"}
_DOCKER_LIMIT_WARNINGS = ("no memory limit support", "no swap limit support",
                          "no pids limit support", "no cpu cfs quota support")


async def _runtime_kind(path: str) -> str:
    _, out = await run_command([path, "--version"], cwd=Path("/"), timeout=15, check=False)
    return "podman" if "podman" in out.lower() else "docker"


async def detect_runtime() -> ContainerRuntime:
    """
    Pick the container runtime (Decision C: Podman first, then Docker) and check
    that it can actually enforce the sandbox limits. Raises SandboxUnavailable
    if it can't. Override with VTEST_CONTAINER_RUNTIME=podman|docker.
    """
    requested = os.environ.get("VTEST_CONTAINER_RUNTIME", "").strip().lower()
    if requested and requested not in ("podman", "docker"):
        raise SandboxUnavailable(f"Unsupported VTEST_CONTAINER_RUNTIME={requested!r}")

    path = None
    for name in ([requested] if requested else ["podman", "docker"]):
        path = shutil.which(name, path=minimal_env()["PATH"])
        if path:
            break
    if not path:
        raise SandboxUnavailable(
            "Neither podman nor docker was found. vtest refuses to run "
            "repository or LLM-generated code on the host without a sandbox."
        )

    kind = await _runtime_kind(path)
    warnings: list[str] = []

    if kind == "podman":
        rc, out = await run_command(
            [path, "info", "--format",
             "{{.Host.Security.Rootless}}|{{range .Host.CgroupControllers}}{{.}} {{end}}"],
            cwd=Path("/"), timeout=30, check=False,
        )
        if rc != 0 or "|" not in out:
            raise SandboxUnavailable(f"`podman info` failed: {out.strip()[:300]}")
        rootless_s, controllers_s = out.strip().split("|", 1)
        rootless = rootless_s.strip() == "true"
        missing = _REQUIRED_CGROUP_CONTROLLERS - set(controllers_s.split())
        if missing:
            raise SandboxUnavailable(
                f"Podman cannot enforce sandbox limits; missing cgroup controllers: {sorted(missing)}"
            )
    else:
        rc, out = await run_command(
            [path, "info", "--format", "{{json .SecurityOptions}}|{{json .Warnings}}"],
            cwd=Path("/"), timeout=30, check=False,
        )
        if rc != 0 or "|" not in out:
            raise SandboxUnavailable(f"`docker info` failed: {out.strip()[:300]}")
        secopts, warns = out.strip().split("|", 1)
        rootless = "rootless" in secopts
        limit_warnings = [w for w in _DOCKER_LIMIT_WARNINGS if w in warns.lower()]
        if limit_warnings:
            raise SandboxUnavailable(f"Docker cannot enforce sandbox limits: {limit_warnings}")

    if not rootless:
        msg = (f"{kind} is running rootful: daemon/group access is root-equivalent. "
               "Rootless Podman is strongly recommended.")
        log.warning(msg)
        warnings.append(msg)

    return ContainerRuntime(path=path, kind=kind, rootless=rootless, warnings=tuple(warnings))


async def get_runtime() -> ContainerRuntime:
    """Cached ``detect_runtime()``. Not locked: running detection twice at once is harmless,
    and a module-level asyncio.Lock breaks if vtest uses more than one event loop."""
    global _runtime_cache
    if _runtime_cache is None:
        _runtime_cache = await detect_runtime()
    return _runtime_cache


async def image_exists(image: str, runtime: ContainerRuntime | None = None) -> bool:
    _validate_image(image)
    rt = runtime or await get_runtime()
    rc, _ = await run_command([rt.path, "image", "inspect", image], cwd=Path("/"), timeout=30, check=False)
    return rc == 0


async def ensure_image(image: str, runtime: ContainerRuntime | None = None) -> None:
    if not await image_exists(image, runtime):
        raise SandboxUnavailable(
            f"Sandbox image {image!r} is not present locally (images are never pulled automatically)."
        )


async def reap_stale_sandboxes(runtime: ContainerRuntime | None = None) -> int:
    """Force-remove containers left behind by a crashed vtest run. Returns how many were removed."""
    rt = runtime or await get_runtime()
    _, out = await run_command(
        [rt.path, "ps", "-aq", "--filter", f"label={SANDBOX_LABEL}"],
        cwd=Path("/"), timeout=30, check=False,
    )
    ids = [i for i in out.split() if re.fullmatch(r"[0-9a-f]{12,64}", i)]
    if ids:
        await run_command([rt.path, "rm", "-f", *ids], cwd=Path("/"), timeout=60, check=False)
    return len(ids)


# ── Sandbox policy & argv construction ─────────────────────────────────────

_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._/:@-]{0,254}$")
_SIZE_RE = re.compile(r"^[1-9][0-9]{0,5}[kmg]$")
_CPUS_RE = re.compile(r"^(0\.[1-9][0-9]?|[1-9](\.[0-9]{1,2})?)$")
_CONTAINER_NAME_RE = re.compile(r"^vtest-(run|app)-[0-9a-f]{12}$")
_ENV_KEY_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_SECRETISH_RE = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|COOKIE|SESSION", re.I)


def _validate_image(image: str) -> None:
    # A leading '-' would be parsed by the CLI as a flag (e.g. "--privileged").
    if not _IMAGE_RE.fullmatch(image):
        raise SandboxUnavailable(f"Invalid image reference: {image!r}")


@dataclass(frozen=True)
class SandboxPolicy:
    image: str
    uid: int = 10001
    network: str = "none"                  # "none" | "container:vtest-app-<12 hex>"
    memory: str = "512m"
    cpus: str = "1.0"
    pids_limit: int = 128
    workdir_size: str = "64m"
    tmp_size: str = "16m"
    shm_size: str = "16m"
    nofile: int = 256
    env: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def validate(self) -> None:
        _validate_image(self.image)
        if not (1000 <= self.uid <= 65533):
            raise SandboxUnavailable("Sandbox uid must be an unprivileged uid (1000-65533)")
        if self.network != "none":
            prefix = "container:"
            if not (self.network.startswith(prefix)
                    and _CONTAINER_NAME_RE.fullmatch(self.network[len(prefix):])
                    and self.network[len(prefix):].startswith("vtest-app-")):
                raise SandboxUnavailable(f"Network mode {self.network!r} is not permitted")
        for size in (self.memory, self.workdir_size, self.tmp_size, self.shm_size):
            if not _SIZE_RE.fullmatch(size):
                raise SandboxUnavailable(f"Invalid size {size!r}")
        if not _CPUS_RE.fullmatch(self.cpus):
            raise SandboxUnavailable(f"Invalid cpus {self.cpus!r}")
        if not (1 <= self.pids_limit <= 1024) or not (16 <= self.nofile <= 4096):
            raise SandboxUnavailable("pids_limit/nofile out of range")
        for key, _ in self.env:
            if not _ENV_KEY_RE.fullmatch(key) or _SECRETISH_RE.search(key):
                raise SandboxUnavailable(f"Environment variable {key!r} may not enter the sandbox")


def _new_name(kind: str) -> str:
    return f"vtest-{kind}-{uuid.uuid4().hex[:12]}"


def _sandbox_argv(
    rt: ContainerRuntime,
    policy: SandboxPolicy,
    name: str,
    cmd: list[str] | tuple[str, ...],
    *,
    interactive: bool,
) -> list[str]:
    policy.validate()
    uid = policy.uid
    # Podman rejects uid=/gid= on --tmpfs and uses "U" (chown to the container user) instead.
    owner_opt = "U" if rt.kind == "podman" else f"uid={uid},gid={uid}"
    argv = [
        rt.path, "run", "--rm",
        "--name", name,
        "--label", SANDBOX_LABEL,
        "--pull=never",
        f"--network={policy.network}",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        f"--user={uid}:{uid}",
        "--read-only",
        "--tmpfs", f"/work:rw,nosuid,nodev,noexec,size={policy.workdir_size},mode=0700,{owner_opt}",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,noexec,size={policy.tmp_size},mode=1777",
        f"--shm-size={policy.shm_size}",
        "--workdir=/work",
        f"--pids-limit={policy.pids_limit}",
        f"--memory={policy.memory}",
        f"--memory-swap={policy.memory}",      # equal to --memory: no swap
        f"--cpus={policy.cpus}",
        f"--ulimit=nofile={policy.nofile}:{policy.nofile}",
        "--ulimit=core=0",
        "--init",
    ]
    if policy.network == "none":
        # Docker rejects --hostname together with --network=container:<id>.
        argv.append("--hostname=vtest-sandbox")
    if rt.kind == "podman":
        argv += [
            "--read-only-tmpfs=false",          # otherwise podman adds writable /run, /var/tmp, /tmp
            "--log-driver=none",                # untrusted output never reaches the journal
        ]
    else:
        argv += ["--log-opt", "max-size=1m", "--log-opt", "max-file=1"]
    if interactive:
        argv.append("--interactive")
    for key, value in policy.env:
        argv += ["--env", f"{key}={value}"]
    argv.append(policy.image)
    argv += list(cmd)
    return argv


async def _force_remove(rt: ContainerRuntime, name: str) -> None:
    """Best effort. Killing the CLI client does NOT stop the container; this does."""
    if not _CONTAINER_NAME_RE.fullmatch(name):
        return
    argv = [rt.path, "rm", "-f"] + (["--time=0"] if rt.kind == "podman" else []) + [name]
    try:
        await run_command(argv, cwd=Path("/"), timeout=30, check=False)
    except SubprocessError as e:
        log.warning("Failed to remove sandbox container %s: %s", name, e)


# ── Payload helper ─────────────────────────────────────────────────────────

_PAYLOAD_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")


def make_tar(files: dict[str, bytes | str]) -> bytes:
    """
    Pack flat files into an in-memory tar to send to a sandbox on stdin.
    Only plain file names are allowed: no directories, no '..', no links.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, content in files.items():
            if not _PAYLOAD_NAME_RE.fullmatch(name) or name in (".", ".."):
                raise ValueError(f"Invalid sandbox payload file name: {name!r}")
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


TREE_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "venv", ".venv", "env", "node_modules", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".nox", "dist", "build",
    "output", ".idea", ".vscode",
})


def _is_secret_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.") or name.endswith((".pem", ".key"))


def make_tree_tar(
    root: Path,
    *,
    max_bytes: int = 128 * 1024 * 1024,
    max_files: int = 20_000,
    skip_dirs: frozenset[str] = TREE_SKIP_DIRS,
) -> bytes:
    """
    Pack a repository tree into an in-memory tar for a sandboxed service.

    Symlinks (files and directories) are never followed or included (M2).
    ``.env`` files and private keys are left out: the app container does not
    need them, and least privilege applies even inside the sandbox.
    Raises ValueError if the tree is larger than ``max_bytes`` or ``max_files``.
    """
    root = root.resolve()
    buf = io.BytesIO()
    total = count = 0
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in skip_dirs and not os.path.islink(os.path.join(dirpath, d))
            )
            for fname in sorted(filenames):
                if _is_secret_file(fname):
                    continue
                full = os.path.join(dirpath, fname)
                try:
                    fd = os.open(full, os.O_RDONLY | os.O_NOFOLLOW)
                except OSError:
                    continue                       # symlink (ELOOP) or unreadable
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    total += st.st_size
                    count += 1
                    if total > max_bytes or count > max_files:
                        raise ValueError(
                            f"Repository too large for the sandbox (>{max_bytes} bytes or >{max_files} files)"
                        )
                    with os.fdopen(fd, "rb", closefd=False) as fh:
                        data = fh.read(st.st_size + 1)
                finally:
                    os.close(fd)
                rel = Path(full).relative_to(root).as_posix()
                info = tarfile.TarInfo(rel)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = 0
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


# ── One-shot sandboxed execution (pytest, k6) ───────────────────────────────

async def run_sandboxed(
    policy: SandboxPolicy,
    cmd: list[str] | tuple[str, ...] = (),
    *,
    stdin_data: bytes | None = None,
    timeout: int = 60,
    max_output: int = MAX_OUTPUT_BYTES,
    runtime: ContainerRuntime | None = None,
) -> ExecResult:
    """
    Run one container to completion and return its output. Treat everything it
    returns as untrusted data: code inside the container can forge any of it.

    Raises:
        SandboxUnavailable: no runtime, limits can't be enforced, or a bad policy.
        SandboxExecError:   the runtime could not start the container.
        SubprocessTimeout:  the timeout was hit; the container was removed.
    """
    rt = runtime or await get_runtime()
    name = _new_name("run")
    argv = _sandbox_argv(rt, policy, name, cmd, interactive=stdin_data is not None)

    try:
        res = await _exec(argv, timeout=timeout, stdin_data=stdin_data, max_output=max_output)
    except BaseException:
        # Timeout, cancellation or error: kill the container, not just the CLI.
        await asyncio.shield(_force_remove(rt, name))
        raise

    # 125 = the runtime itself failed (bad flag, missing image, cgroup error).
    # 126/127 = the image's command could not be invoked or was not found.
    if res.returncode in (125, 126, 127):
        raise SandboxExecError(
            f"{rt.kind} could not run sandbox (exit {res.returncode}): {res.stderr.strip()[:500]}"
        )
    return res


# ── Long-running sandboxed service (target app for the stress agent) ────────

class SandboxedService:
    """
    Run the target app in a container with ``--network=none`` (Decision A).
    k6 joins its network namespace through ``network_ref``, so the only network
    either container can see is the shared loopback.

        async with SandboxedService(policy, ["uvicorn", "main:app"], stdin_data=tar) as app:
            await app.wait_running()
            await run_sandboxed(K6Policy(network=app.network_ref), ...)

    The container is force-removed on exit, and also after ``max_lifetime``
    seconds as a safety net.
    """

    def __init__(
        self,
        policy: SandboxPolicy,
        cmd: list[str] | tuple[str, ...],
        *,
        stdin_data: bytes | None = None,
        max_lifetime: int = 300,
        max_output: int = MAX_OUTPUT_BYTES,
        runtime: ContainerRuntime | None = None,
    ) -> None:
        if policy.network != "none":
            raise SandboxUnavailable("A sandboxed service must use network=none")
        self.policy = policy
        self.cmd = list(cmd)
        self.stdin_data = stdin_data
        self.max_lifetime = max_lifetime
        self.max_output = max_output
        self._runtime = runtime
        self.name = _new_name("app")
        self._rt: ContainerRuntime | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._tasks: list[asyncio.Task] = []
        self._budget = _OutputBudget(max_output)
        self._out = bytearray()
        self._err = bytearray()

    @property
    def network_ref(self) -> str:
        return f"container:{self.name}"

    @property
    def exited(self) -> bool:
        return self._proc is not None and self._proc.returncode is not None

    def output(self) -> str:
        """Untrusted app output captured so far (capped)."""
        text = _decode(self._out) + _decode(self._err)
        if self._budget.truncated:
            text += f"\n[vtest: output truncated at {self.max_output} bytes]\n"
        return text

    async def __aenter__(self) -> "SandboxedService":
        self._rt = self._runtime or await get_runtime()
        argv = _sandbox_argv(self._rt, self.policy, self.name, self.cmd,
                             interactive=self.stdin_data is not None)
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *argv,
                env=minimal_env(),
                stdin=asyncio.subprocess.PIPE if self.stdin_data is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as e:
            raise SubprocessError(f"Failed to start {self._rt.kind}: {e}") from e

        if self.stdin_data is not None and self._proc.stdin is not None:
            try:
                self._proc.stdin.write(self.stdin_data)
                await self._proc.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                self._proc.stdin.close()

        self._tasks = [
            asyncio.create_task(_drain(self._proc.stdout, self._budget, self._out)),
            asyncio.create_task(_drain(self._proc.stderr, self._budget, self._err)),
            asyncio.create_task(self._watchdog()),
        ]
        return self

    async def _watchdog(self) -> None:
        await asyncio.sleep(self.max_lifetime)
        log.warning("Sandboxed service %s exceeded max_lifetime=%ss; removing", self.name, self.max_lifetime)
        await self._teardown()

    async def wait_running(self, timeout: float = 30, interval: float = 0.5) -> None:
        """Wait until the container is running. This does not check that the app is listening yet."""
        assert self._rt is not None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            if self.exited:
                raise SandboxExecError(f"Service exited early (code {self._proc.returncode}):\n{self.output()[-2000:]}")
            rc, out = await run_command(
                [self._rt.path, "inspect", "--format", "{{.State.Running}}", self.name],
                cwd=Path("/"), timeout=15, check=False,
            )
            if rc == 0 and out.strip() == "true":
                return
            await asyncio.sleep(interval)
        raise SubprocessTimeout(f"Service {self.name} did not start within {timeout}s")

    async def _teardown(self) -> None:
        if self._rt is not None:
            await _force_remove(self._rt, self.name)
        if self._proc is not None and self._proc.returncode is None:
            _kill_group(self._proc.pid)
            try:
                await asyncio.wait_for(self._proc.wait(), timeout=_KILL_GRACE_SECONDS)
            except asyncio.TimeoutError:
                pass

    async def __aexit__(self, *exc) -> None:
        current = asyncio.current_task()
        for t in self._tasks:
            if t is not current:
                t.cancel()
        await asyncio.shield(self._teardown())
        await asyncio.gather(*(t for t in self._tasks if t is not current), return_exceptions=True)


# ── Dependency image (Decision B: --install-deps) ───────────────────────────

_REQ_NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
_REQ_EXTRAS = r"(?:\[\s*" + _REQ_NAME + r"(?:\s*,\s*" + _REQ_NAME + r")*\s*\])?"
_REQ_VERSION = r"(?:===|==|!=|~=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+"
_REQ_SPEC = r"(?:" + _REQ_VERSION + r"(?:\s*,\s*" + _REQ_VERSION + r")*)?"
_REQ_MARKER = r"(?:\s*;\s*[A-Za-z0-9_ .<>=!~\"'()]+)?"
_REQ_LINE_RE = re.compile(r"^" + _REQ_NAME + r"\s*" + _REQ_EXTRAS + r"\s*" + _REQ_SPEC + _REQ_MARKER + r"$")


def sanitize_requirements(text: str) -> tuple[list[str], list[str]]:
    """
    Keep only plain PEP 508 ``name[extras] <spec> ; marker`` lines. Reject pip
    options (``-r``, ``-e``, ``--index-url``, ``--extra-index-url``, ...),
    URLs, local paths and ``@`` direct references. Each of these could point
    pip at an attacker-chosen source or local code.

    Returns (accepted, rejected).
    """
    accepted: list[str] = []
    rejected: list[str] = []
    for raw in text.splitlines():
        line = re.split(r"(?:^|\s)#", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        if (line.startswith("-") or "://" in line or "@" in line
                or "/" in line or "\\" in line or not _REQ_LINE_RE.fullmatch(line)):
            rejected.append(raw.strip())
        else:
            accepted.append(line)
    return accepted, rejected


def _deps_containerfile(base_image: str, uid: int) -> str:
    return (
        f"FROM {base_image}\n"
        "USER 0:0\n"
        "COPY requirements.txt /opt/vtest-deps/requirements.txt\n"
        # --only-binary=:all: means wheels only: no setup.py / build backend code runs during the build.
        "RUN python3 -m pip install --no-cache-dir --disable-pip-version-check --no-input --root-user-action=ignore \\\n"
        "      --only-binary=:all: --no-compile \\\n"
        "      --target /opt/vtest-deps/site -r /opt/vtest-deps/requirements.txt \\\n"
        " && chmod -R a+rX,go-w /opt/vtest-deps\n"
        "ENV PYTHONPATH=/opt/vtest-deps/site PATH=/opt/vtest-deps/site/bin:/usr/local/bin:/usr/bin:/bin\n"
        f"USER {uid}:{uid}\n"
    )


@dataclass
class DepsImageResult:
    image: str
    accepted: list[str]
    rejected: list[str]
    built: bool
    log: str = ""


async def build_dependency_image(
    requirements_text: str,
    *,
    base_image: str = PYTEST_IMAGE,
    uid: int = 10001,
    timeout: int = 600,
    runtime: ContainerRuntime | None = None,
) -> DepsImageResult:
    """
    Build (or reuse) ``localhost/vtest-deps:<hash>`` = base image + the repo's
    wheel-only dependencies.

    The build has network access (pip must download wheels) but receives only
    the sanitised requirements file: no repository code and no host secrets
    (the build process gets ``minimal_env()``). With Podman, build containers
    also run with all capabilities dropped and a memory cap.
    """
    _validate_image(base_image)
    rt = runtime or await get_runtime()
    accepted, rejected = sanitize_requirements(requirements_text)
    if not accepted:
        return DepsImageResult(image=base_image, accepted=[], rejected=rejected, built=False)

    req_body = "\n".join(sorted(set(accepted))) + "\n"
    digest = hashlib.sha256(f"{base_image}\n{uid}\n{req_body}".encode()).hexdigest()[:16]
    tag = f"{DEPS_IMAGE_REPO}:{digest}"

    if await image_exists(tag, rt):
        return DepsImageResult(image=tag, accepted=accepted, rejected=rejected, built=False)
    await ensure_image(base_image, rt)

    with tempfile.TemporaryDirectory(prefix="vtest_deps_") as ctx:
        ctx_path = Path(ctx)
        (ctx_path / "requirements.txt").write_text(req_body)
        (ctx_path / "Containerfile").write_text(_deps_containerfile(base_image, uid))

        argv = [rt.path, "build", "--pull=never", "--tag", tag,
                "--label", SANDBOX_LABEL, "--file", str(ctx_path / "Containerfile")]
        if rt.kind == "podman":
            argv += ["--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=1g"]
        argv.append(str(ctx_path))

        rc, out = await run_command(argv, cwd=ctx_path, timeout=timeout, check=False)

    if rc != 0:
        raise SandboxExecError(f"Dependency image build failed (exit {rc}):\n{out[-4000:]}")
    return DepsImageResult(image=tag, accepted=accepted, rejected=rejected, built=True, log=out)
