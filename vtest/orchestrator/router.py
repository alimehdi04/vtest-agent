"""
Orchestrator routing: decide which sub-agents to run.

L4: the LLM's JSON is validated against a strict Pydantic model. Every
execution flag defaults to False, values must be real booleans, and unknown
keys are rejected. Invalid output raises StrategyValidationError, and nothing
runs on a guess.

M5: without --allow-llm-upload no Groq call is made. ``local_strategy()``
picks the agents deterministically instead.
"""

import json

from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator

from vtest.core.llm import ask

MAX_REASONING_CHARS = 500
ROUTER_MAX_TOKENS = 1024
WEB_FRAMEWORKS = {"FastAPI", "Flask", "Django", "Next.js", "Express", "Spring Boot", "Node.js"}


class StrategyValidationError(ValueError):
    """The LLM's strategy did not match the TestingStrategy schema."""


class TestingStrategy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    run_unit: StrictBool = False
    run_security: StrictBool = False
    run_stress: StrictBool = False
    reasoning: str = Field(default="")

    @field_validator("reasoning")
    @classmethod
    def _cap_reasoning(cls, v: str) -> str:
        # Untrusted LLM text: keep it short and single-line for display.
        return " ".join(v.split())[:MAX_REASONING_CHARS]


def parse_strategy(raw: str) -> TestingStrategy:
    """Parse and strictly validate the LLM's JSON reply."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError) as e:
        raise StrategyValidationError(f"Router reply is not valid JSON: {e}") from e
    if not isinstance(data, dict):
        raise StrategyValidationError("Router reply must be a JSON object")
    try:
        return TestingStrategy.model_validate(data)
    except ValidationError as e:
        problems = "; ".join(f"{'.'.join(map(str, err['loc'])) or '<root>'}: {err['msg']}" for err in e.errors())
        raise StrategyValidationError(f"Router reply failed validation: {problems}") from e


def get_testing_strategy(context: dict) -> TestingStrategy:
    """
    Pass the codebase metadata (language, framework, file count; no source
    code) to the LLM to decide which testing agents to run. Requires
    --allow-llm-upload (enforced in vtest.core.llm.ask).
    """
    prompt = f"""
    You are the Orchestrator AI for a local code testing agent.
    Analyze the following codebase context and decide which testing sub-agents to run.

    Context:
    - Primary Language: {context.get('primary_language')}
    - Framework: {context.get('framework')}
    - Total Files: {context.get('total_files')}

    Rules:
    - 'run_unit': true for almost all codebases with logic.
    - 'run_security': true for all codebases.
    - 'run_stress': true ONLY if the framework typically runs a web server or API (e.g., Next.js, Spring Boot, FastAPI, Node.js). False for simple scripts.

    You must respond ONLY with a valid JSON object matching this exact schema, with no other keys:
    {{
        "run_unit": true/false,
        "run_security": true/false,
        "run_stress": true/false,
        "reasoning": "string explaining why"
    }}
    """

    raw = ask(
        prompt,
        temperature=0.1,
        max_tokens=ROUTER_MAX_TOKENS,
        response_format={"type": "json_object"},
    )
    return parse_strategy(raw)


def local_strategy(context: dict, app_cmd_given: bool) -> TestingStrategy:
    """
    Deterministic strategy used when LLM upload is not allowed. Unit tests need
    the LLM to write them, so they're off. Security (local Semgrep) is on.
    Stress runs only for web frameworks when the user supplied --app-cmd.
    """
    stress = bool(app_cmd_given and context.get("framework") in WEB_FRAMEWORKS)
    return TestingStrategy(
        run_unit=False,
        run_security=True,
        run_stress=stress,
        reasoning=(
            "LLM upload not allowed: no data sent to Groq. Running local static analysis"
            + (" and the sandboxed stress test." if stress else ".")
            + " Pass --allow-llm-upload to enable LLM-generated unit tests."
        ),
    )
