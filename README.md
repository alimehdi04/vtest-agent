# 🛡️ vtest-agent

**An Autonomous, Local Code Diagnostic Agent for AI-Assisted Development**

The rapid adoption of AI-assisted code generation tools ("vibe-coding") enables rapid development but routinely bypasses unit testing, security reviews, and performance evaluations. **vtest-agent** is a local, terminal-native AI agent that addresses this gap.

It orchestrates three specialized sub-agents in parallel to assess code quality without requiring cloud uploads, external CI/CD pipelines, or GitHub repositories. Upon completion, the agent generates a machine-readable, XML-tagged `fix-brief.md` formatted specifically for downstream coding agents (like Claude Code, Cursor, or AntiGravity) to autonomously remediate the identified defects.

## ✨ Features

* **AST-Based Semantic Ingestion:** Uses Python's Abstract Syntax Tree (`ast`) to extract only function and class signatures, achieving ~70% token reduction to prevent LLM context window bloat.
* **Smart Pathspec Filtering:** Dynamically reads local `.gitignore` rules via `pathspec` to instantly bypass `node_modules`, `venv`, and binary directories without hardcoding.
* **Parallel Multi-Agent Orchestration:** Dispatches Unit, Security, and Stress agents concurrently via `asyncio.gather()` for maximum performance.
* **Local-First Sandboxing:** Executes LLM-generated tests in isolated temporary directories with strict timeouts to prevent thread deadlocks.
* **AI-to-AI Handoff:** Generates GitHub Flavored Markdown (GFM) reports for humans and strict XML-tagged remediation prompts (`<vibe_audit>`) for AI coding assistants.
* **Deterministic Parsing:** Enforces strict Pydantic models for all agent findings to eliminate LLM conversational hallucination.

## 🛠️ Architecture & Tech Stack

* **Core/CLI:** Python 3.12+, Typer, Rich
* **LLM Engine:** Groq API (Llama 3.x / Mixtral routing)
* **Static Analysis:** Semgrep OSS (OWASP Top 10 / Auto rulesets)
* **Performance Testing:** k6
* **Data Validation:** Pydantic
* **Graphing & Context:** NetworkX, Pathspec

## 🚀 Installation

**Prerequisites:**
You must have [Semgrep](https://www.google.com/search?q=https://semgrep.dev/docs/getting-started/&utm_source=gemini) and [k6](https://k6.io/docs/get-started/installation/?utm_source=gemini) installed on your host machine to run the Security and Stress sub-agents.

Install the CLI globally directly from GitHub using pip:

```bash
pip install git+https://github.com/alimehdi04/vtest-agent.git

```

**Configuration:**
The agent requires a Groq API key to power the LLM evaluation engine. Export it in your terminal session or add it to a local `.env` file in your target project directory:

```bash
export GROQ_API_KEY="your_api_key_here"

```

## 💻 Usage

Navigate to any codebase on your machine and run the full diagnostic suite:

```bash
vtest analyze .

```

To run a stress test against a specific local port (default is 3000):

```bash
vtest analyze . --port 8000

```

To run a specific agent in standalone mode:

```bash
vtest security .
vtest stress --port 8000

```

## 📊 Outputs & AI Remediation

Upon completion, `vtest` renders a color-coded Rich matrix in your terminal and generates two files in the `output/` directory:

1. **`audit-report.md`**: A human-readable summary table with GFM `<details>` collapsible raw execution logs.
2. **`fix-brief.md`**: A machine-readable XML prompt containing the exact execution traces, line numbers, and rule violations.

**The Handoff:** Feed `fix-brief.md` directly into Claude Code, Cursor, or your preferred agentic CLI to watch the AI autonomously patch the identified security and logic flaws.

---

**Author:** Ali Mehdi Naqvi
*Developed as a B.Tech Computer Science and Engineering Minor Project at Jamia Millia Islamia.*