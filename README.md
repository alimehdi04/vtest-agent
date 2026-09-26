# 🛡️ vtest

**An AI-Powered Local Code Diagnostic Agent for Automated Unit Testing, Security Auditing, and Performance Analysis.**

The rapid adoption of AI-assisted code generation tools ("vibe-coding") enables rapid development but routinely bypasses unit testing, security reviews, and performance evaluations. **vtest** is a local, terminal-native AI agent that addresses this gap. 

It orchestrates three specialized sub-agents in parallel to assess code quality without requiring cloud uploads, external CI/CD pipelines, or GitHub repositories. Upon completion, the agent generates a machine-readable, XML-tagged `fix-brief.md` formatted specifically for downstream coding agents (like Claude Code or Cursor) to autonomously remediate the identified defects.

## ✨ Features

* **AST-Based Semantic Ingestion:** Uses Python's Abstract Syntax Tree (`ast`) to extract only function and class signatures, achieving ~70% token reduction to prevent LLM context window bloat.
* **Parallel Multi-Agent Orchestration:** Dispatches Unit, Security, and Stress agents concurrently via `asyncio.gather()`.
* **Local-First Sandboxing:** Executes LLM-generated tests in isolated temporary directories with strict timeouts to prevent thread deadlocks.
* **AI-to-AI Handoff:** Generates GitHub Flavored Markdown (GFM) reports for humans and strict XML-tagged remediation prompts for AI coding assistants.
* **Deterministic Parsing:** Enforces strict Pydantic models for all agent findings to eliminate LLM conversational hallucination.

## 🛠️ Architecture & Tech Stack

* **Core/CLI:** Python 3.12, Typer, Rich
* **LLM Engine:** Groq API
* **Static Analysis:** Semgrep OSS (OWASP Top 10)
* **Performance Testing:** k6
* **Data Validation:** Pydantic
* **Graphing:** NetworkX, Pathspec

## 🚀 Installation

**Prerequisites:** 
You must have [Semgrep](https://semgrep.dev/) and [k6](https://k6.io/docs/get-started/installation/) installed on your host machine.

```bash
# Clone the repository
git clone https://github.com/alimehdi04/vtest-agent.git
cd vtest

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

```

**Configuration:**
Create a `.env` file in the root directory and add your Groq API key:

```env
GROQ_API_KEY=your_api_key_here

```

## 💻 Usage

Run the full diagnostic suite on your local directory:

```bash
python -m vtest.main analyze .

```

To run a specific agent in standalone mode:

```bash
python -m vtest.main security .
python -m vtest.main stress --port 3000

```

## 📊 Outputs

Upon completion, `vtest` generates two files in the `output/` directory:

1. `audit-report.md`: A human-readable summary table with GFM `<details>` collapsible raw execution logs.
2. `fix-brief.md`: A machine-readable XML prompt containing the exact execution traces, line numbers, and rule violations. Feed this file directly into Claude Code or Cursor for autonomous codebase remediation.

---

**Author:** Ali Mehdi Naqvi