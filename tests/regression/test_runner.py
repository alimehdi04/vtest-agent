"""Host-side process execution: env scrubbing (H3), process-group kill and output cap (M4), payload safety."""

import asyncio
import io
import os
import subprocess
import sys
import tarfile
import time
import uuid
from pathlib import Path

import pytest

from vtest.core import runner as r

ROOT = Path("/")


def run(cmd, **kw):
    return asyncio.run(r.run_command(cmd, cwd=ROOT, **kw))


def test_child_env_contains_only_allowlisted_keys(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk_canary_secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws_canary")
    monkeypatch.setenv("PYTEST_ADDOPTS", "-p evil")
    _, out = run(["env"], check=False)
    keys = {line.split("=", 1)[0] for line in out.splitlines() if "=" in line}
    assert "canary" not in out
    assert keys <= {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE"}


def test_timeout_kills_the_whole_process_group():
    marker = f"vtest-orphan-{uuid.uuid4().hex}"
    sleeper = f"import time; time.sleep(300)  # {marker}"
    script = f"{sys.executable} -c '{sleeper}' & {sys.executable} -c '{sleeper}' & wait"
    start = time.monotonic()
    with pytest.raises(r.SubprocessTimeout):
        run(["sh", "-c", script], timeout=2)
    assert time.monotonic() - start < 10
    time.sleep(0.5)
    left = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    assert left.stdout.strip() == "", "grandchild processes survived the timeout"


def test_merged_output_is_capped_at_one_megabyte():
    _, out = run(["sh", "-c", "head -c 5000000 /dev/zero | tr '\\0' A"], check=False)
    assert len(out.encode()) <= r.MAX_OUTPUT_BYTES + 100
    assert "truncated at 1048576" in out


def test_output_cap_is_shared_by_stdout_and_stderr():
    res = asyncio.run(r._exec(
        ["sh", "-c", "head -c 900000 /dev/zero | tr '\\0' A; head -c 900000 /dev/zero | tr '\\0' B >&2"], cwd=ROOT))
    assert res.truncated
    assert len(res.stdout.encode()) + len(res.stderr.encode()) <= r.MAX_OUTPUT_BYTES + 100


def test_run_command_compatibility():
    with pytest.raises(r.SubprocessError):
        run(["false"])
    with pytest.raises(r.SubprocessError, match="System execution failed"):
        run(["/nonexistent-binary"])
    rc, out = run(["echo", "hi"])
    assert (rc, out.strip()) == (0, "hi")


@pytest.mark.parametrize("bad", [
    dict(image="--privileged"),
    dict(image=r.PYTEST_IMAGE, network="host"),
    dict(image=r.PYTEST_IMAGE, network="container:someone-else"),
    dict(image=r.PYTEST_IMAGE, uid=0),
    dict(image=r.PYTEST_IMAGE, env=(("GROQ_API_KEY", "x"),)),
    dict(image=r.PYTEST_IMAGE, memory="0"),
])
def test_sandbox_policy_rejects_dangerous_settings(bad):
    with pytest.raises(r.SandboxUnavailable):
        r.SandboxPolicy(**bad).validate()


def test_sandbox_policy_allows_k6_joining_an_app_namespace():
    r.SandboxPolicy(image=r.K6_IMAGE, uid=12345, network="container:vtest-app-0123456789ab").validate()


@pytest.mark.parametrize("kind", ["podman", "docker"])
def test_sandbox_argv_has_all_hardening_flags(kind):
    rt = r.ContainerRuntime(path=f"/usr/bin/{kind}", kind=kind, rootless=True)
    argv = r._sandbox_argv(rt, r.SandboxPolicy(image=r.PYTEST_IMAGE), "vtest-run-0123456789ab", [], interactive=True)
    for flag in ["--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--user=10001:10001",
                 "--read-only", "--pids-limit=128", "--memory=512m", "--memory-swap=512m", "--pull=never", "--init"]:
        assert flag in argv
    assert not any(a == "--env" or a.startswith("--env=") for a in argv)
    assert ("--read-only-tmpfs=false" in argv) == (kind == "podman")


def test_requirements_sanitiser_keeps_only_plain_specs():
    accepted, rejected = r.sanitize_requirements(
        "fastapi==0.110.0\nrequests[socks]>=2.0,<3 ; python_version >= \"3.8\"\n# c\nnumpy  # pinned\n"
        "-r other.txt\n-e .\n--extra-index-url https://evil\nfoo @ https://evil/x.whl\n./localpkg\ngit+https://x/y\n")
    assert accepted == ["fastapi==0.110.0", 'requests[socks]>=2.0,<3 ; python_version >= "3.8"', "numpy"]
    assert len(rejected) == 6


@pytest.mark.parametrize("name", ["../x", "a/b", "/abs", ".."])
def test_flat_payload_rejects_paths(name):
    with pytest.raises(ValueError):
        r.make_tar({name: b""})


def test_tree_tar_skips_secrets_and_symlinks_and_append_adds_last(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("x = 1\n")
    (tmp_path / ".env").write_text("SECRET=1\n")
    (tmp_path / "id_rsa.key").write_text("key\n")
    outside = tmp_path.parent / f"outside-{uuid.uuid4().hex}"
    outside.mkdir()
    (outside / "stolen.py").write_text("s = 1\n")
    (tmp_path / "link.py").symlink_to(outside / "stolen.py")
    (tmp_path / "linkdir").symlink_to(outside)
    tree = r.make_tree_tar(tmp_path)
    names = tarfile.open(fileobj=io.BytesIO(tree)).getnames()
    assert names == ["pkg/mod.py"]
    names = tarfile.open(fileobj=io.BytesIO(r.append_to_tar(tree, {"test_generated.py": "1"}))).getnames()
    assert names == ["pkg/mod.py", "test_generated.py"]


def test_tree_tar_enforces_size_limit(tmp_path):
    (tmp_path / "big.bin").write_bytes(os.urandom(2048))
    with pytest.raises(ValueError, match="too large"):
        r.make_tree_tar(tmp_path, max_bytes=1024)
