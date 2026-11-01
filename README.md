# 🛡️ vtest-agent

**An Autonomous, Local Code Diagnostic Agent for AI-Assisted Development**

The rapid adoption of AI-assisted code generation tools ("vibe-coding") enables rapid development but routinely bypasses unit testing, security reviews, and performance evaluations. **vtest-agent** is a local, terminal-native AI agent that addresses this gap.

It orchestrates three specialized sub-agents in parallel to assess code quality without external CI/CD pipelines or GitHub repositories. Repository code is executed only inside a locked-down container sandbox, and nothing is sent to an LLM unless you explicitly consent. Upon completion, the agent generates a machine-readable, XML-tagged `fix-brief.md` formatted specifically for downstream coding agents (like Claude Code, Cursor, or AntiGravity) to remediate the identified defects.

## ✨ Features

* **Container Sandbox for Untrusted Code:** Repository code, LLM-generated tests, the target app and k6 all run in rootless Podman (or Docker) containers with no network, no capabilities, an unprivileged user and strict PID/memory/CPU limits. See [Security Architecture](#-security-architecture).
* **Privacy by Default:** No code or metadata is sent to the Groq API unless you pass `--allow-llm-upload`. When you do, apparent secrets are redacted first.
* **AST-Based Semantic Ingestion:** Uses Python's Abstract Syntax Tree (`ast`) to extract only function and class signatures, cutting tokens by ~70% so prompts stay small.
* **Smart Pathspec Filtering:** Reads local `.gitignore` rules via `pathspec` to skip `node_modules`, `venv`, and binary directories without hardcoding.
* **Parallel Multi-Agent Orchestration:** Dispatches Unit, Security, and Stress agents concurrently via `asyncio.gather()`.
* **AI-to-AI Handoff:** Generates GitHub Flavored Markdown (GFM) reports for humans and strictly escaped XML remediation prompts (`<vibe_audit>`) for AI coding assistants.
* **Deterministic Parsing:** Strict Pydantic models validate agent findings and the LLM's routing decision.

## 🛠️ Architecture & Tech Stack

* **Core/CLI:** Python 3.10+, Typer, Rich
* **Sandbox:** Podman (rootless, recommended) or Docker
* **LLM Engine:** Groq API (`openai/gpt-oss-20b`), opt-in
* **Static Analysis:** Semgrep OSS (`p/owasp-top-ten` by default, or a local ruleset)
* **Performance Testing:** k6 (runs inside the sandbox)
* **Data Validation:** Pydantic
* **Graphing & Context:** NetworkX, Pathspec

## 🔒 Security Architecture

vtest analyzes code it does not trust. A repository can contain hostile code, and LLM-written tests are untrusted too. The design assumes both may be malicious.

### What runs where

| Component | Runs on | Why |
|---|---|---|
| CLI, ingestion, report writing | Host | Trusted vtest code; never executes repository code |
| Semgrep | Host | Trusted tool; static analysis only (reads files, executes nothing) |
| pytest + repository code + LLM-generated tests | **Sandbox** (`localhost/vtest-pytest:1`) | Executes untrusted code |
| Target app (stress test) | **Sandbox** (base or `--install-deps` image) | Executes untrusted code |
| k6 load generator | **Sandbox** (`localhost/vtest-k6:1`) | Joins only the app's isolated network |

### Sandbox guarantees

Every sandbox container is started with:

* `--network=none`: no internet or LAN access. For stress tests, k6 joins the app container's network namespace (`--network=container:vtest-app-<id>`), which contains only a loopback interface.
* `--cap-drop=ALL` and `--security-opt=no-new-privileges`
* An unprivileged user (uid 10001; 12345 for k6), never root
* A read-only root filesystem, plus small `noexec` tmpfs mounts for `/work` and `/tmp`
* `--pids-limit=128`, `--memory=512m` with swap disabled, `--cpus=1.0`, file-descriptor limits (the app container gets 1 GB / 256 PIDs / 2 CPUs)
* **No host environment variables:** `GROQ_API_KEY` and other secrets never enter a container
* **No host directories mounted:** files are streamed in as a tar archive, and `.env` files, private keys and symlinks are excluded
* Hard timeouts: on expiry the container is force-removed and the whole process group is killed. Output is capped at 1 MB.

vtest **fails closed**: if neither Podman nor Docker is available, or the runtime cannot enforce the limits (missing cgroup controllers), the unit and stress agents are disabled. Repository code is never run on the host as a fallback.

### What is sent to the LLM (only with `--allow-llm-upload`)

* **Routing call:** language, framework and file count only. No source code.
* **Unit-test generation:** for each Python file (up to 50), function/class signatures and docstrings. If a file can't be parsed, its first 3,000 characters are sent instead.
* Before sending, a regex scrubber redacts apparent credentials: private keys, AWS/GitHub/GitLab/Slack/Groq/OpenAI/Anthropic/Stripe/Google keys, JWTs, passwords in URLs, and quoted values assigned to names like `password`, `secret`, `token` or `api_key`. Redaction is best-effort: an unusual secret format can still get through.
* Repository content is wrapped in unguessable delimiters and the model is told to treat it as data, never instructions.
* Each request is capped at 4,096 output tokens (1,024 for routing), with a 60-second timeout and at most 2 retries. The routing reply must match a strict schema, or the run stops.

Without `--allow-llm-upload`, vtest makes **no** Groq requests: it runs Semgrep, and the stress test if you give `--app-cmd` for a web framework. LLM-generated unit tests are skipped.

### Report hardening

* `fix-brief.md` is built with `xml.etree.ElementTree`. All text is escaped, so tool output cannot close tags or forge `<instructions>`. Untrusted elements are marked `trust="untrusted"`.
* `audit-report.md` escapes Markdown/HTML and fences logs so they can't break out of their code blocks.
* Reports are written only to `<scanned repo>/output/`, and never through a symlink: a symlinked `output/` directory or report file is rejected.

> ⚠️ **Feeding `fix-brief.md` to an AI agent:** escaping stops structural injection, but the execution traces still contain text produced by the scanned code. Review the brief before you let an autonomous agent act on it, and don't let the agent run commands copied from traces.

## 🚀 Installation

**Prerequisites:**

* **Python 3.10+**
* **[Podman](https://podman.io/docs/installation)** (recommended; rootless by default on Fedora) **or [Docker](https://docs.docker.com/engine/install/)**. Required for the Unit and Stress agents. Prefer rootless mode: access to a rootful Docker daemon is equivalent to root on the host.
* **[Semgrep](https://semgrep.dev/docs/getting-started/quickstart)** on the host for the Security agent (also installed by `requirements.txt` below).
* k6 is **not** needed on the host; it runs inside its sandbox image.

Install from source:

```bash
git clone https://github.com/alimehdi04/vtest-agent.git
cd vtest-agent
pip install -r requirements.txt
pip install .
```

**Build the sandbox images (once):**

```bash
vtest sandbox-build
```

This builds `localhost/vtest-pytest:1` and `localhost/vtest-k6:1` from the Containerfiles in `vtest/sandbox/`. Base images are pinned by digest and pulled from Docker Hub, so this step needs network access. After that, sandbox images are never pulled automatically (`--pull=never`). vtest uses Podman when it's installed; set `VTEST_CONTAINER_RUNTIME=docker` to force Docker.

**Configuration (only needed for `--allow-llm-upload`):**

```bash
export GROQ_API_KEY="your_api_key_here"
```

Export the key in your shell. A `.env` file is only picked up from the vtest source tree, not from the project being scanned.

## 💻 Usage

**Privacy-preserving run (default):** no data is sent to Groq; Semgrep runs locally.

```bash
vtest analyze .
```

**Full suite with LLM-generated unit tests:** you consent to uploading redacted code skeletons to Groq.

```bash
vtest analyze . --allow-llm-upload
```

**Stress testing:** vtest starts your app inside the sandbox, so you must tell it how. The app must listen on `--port` (default 3000) on `127.0.0.1` or `0.0.0.0` inside the container. Add `--install-deps` so the app's dependencies (e.g. `fastapi`, `uvicorn`) are available.

```bash
vtest analyze . --allow-llm-upload --install-deps \
  --app-cmd "python3 -m uvicorn main:app --host 127.0.0.1 --port 8000" --port 8000
```

**Standalone agents:**

```bash
vtest security .                                   # Semgrep only (host, static analysis)
vtest security . --semgrep-config ./rules/          # fully offline, with a local ruleset
vtest stress . --install-deps --app-cmd "python3 app.py" --port 5000
```

### Command & flag reference

| Command / flag | Description |
|---|---|
| `vtest sandbox-build` | Builds the pytest and k6 sandbox images. Run once before using the Unit or Stress agents. |
| `vtest analyze PATH` | Runs the full suite. Without `--allow-llm-upload`, makes no LLM calls. |
| `--allow-llm-upload` | Consent to sending redacted code skeletons and repo metadata to the Groq API. Required for LLM routing and LLM-generated unit tests. Off by default. |
| `--app-cmd "CMD"` | Command that starts the target app **inside the sandbox** (e.g. `"python3 -m uvicorn main:app --port 3000"`). Required for stress testing. |
| `--port N` | Port the app listens on inside the sandbox (default 3000). |
| `--install-deps` | Builds a sandbox image with the repo's root `requirements.txt`, using **wheels only** (`pip --only-binary=:all:`), so no package setup scripts run. Lines with `-r`, `-e`, index URLs, direct URLs or local paths are ignored. If the build fails (e.g. a package has no wheel), vtest falls back to the base image. |
| `--semgrep-config CFG` | Semgrep ruleset: a registry pack (default `p/owasp-top-ten`, downloaded from semgrep.dev, with telemetry off) or a local rules file/directory for fully offline scans. |
| `vtest security PATH` | Semgrep only. Accepts `--semgrep-config`. |
| `vtest stress PATH --app-cmd "CMD"` | Stress test only. Accepts `--port` and `--install-deps`. |
| `VTEST_CONTAINER_RUNTIME` | Env var: `podman` or `docker` to override runtime detection. |

**What the stress test does:** routes found in `@app.get("/...")`-style decorators are validated (path characters only; parameters like `{id}` become `1`) and passed as data to a fixed k6 script bundled with vtest. The script ramps to 10 virtual users for about 10 seconds, then vtest reports p95 latency and the request failure rate.

## 📊 Outputs & AI Remediation

Upon completion, `vtest` renders a color-coded Rich matrix in your terminal and generates two files in `<scanned repo>/output/`:

1. **`audit-report.md`**: A human-readable summary table with GFM `<details>` collapsible raw execution logs.
2. **`fix-brief.md`**: A machine-readable `<vibe_audit>` XML prompt containing execution traces, locations, and rule violations. Untrusted content is escaped and labelled `trust="untrusted"`.

**The Handoff:** Review `fix-brief.md`, then feed it into Claude Code, Cursor, or your preferred agentic CLI to patch the identified security and logic flaws.

## ⚠️ Known Limitations

* The sandbox shares the host kernel. A kernel exploit could escape it; for stronger isolation, consider gVisor or a VM.
* Secret redaction is regex-based and best-effort.
* Sandboxed apps receive no environment variables and no `.env` file. Apps that require configuration at startup may fail to start.
* Report writing relies on POSIX features (`O_NOFOLLOW`, `dir_fd`). Tested on Linux with rootless Podman; Windows is not supported, and macOS and the Docker runtime are untested.

---

**Author:** Ali Mehdi Naqvi
*Developed as a B.Tech Computer Science and Engineering Minor Project at Jamia Millia Islamia.*
