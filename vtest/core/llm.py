"""
Groq LLM wrapper.

* M5: nothing is sent unless the user explicitly allows it
  (``vtest analyze --allow-llm-upload`` calls ``allow_uploads(True)``).
  Every LLM call in vtest goes through ``ask()``, so this one gate covers them all.
* L2: every request has a strict output-token cap, a request timeout and a
  bounded retry count.
"""

import os

from dotenv import load_dotenv
from groq import Groq

load_dotenv()

MODEL = "openai/gpt-oss-20b"
DEFAULT_MAX_TOKENS = 4096          # hard cap on completion tokens, including hidden reasoning tokens
MAX_TOKENS_CEILING = 8192          # no caller may ask for more than this
REQUEST_TIMEOUT_SECONDS = 60.0
MAX_RETRIES = 2

_upload_allowed = False


class LLMUploadNotAllowed(RuntimeError):
    """Raised when code would be sent to the LLM without the user's explicit consent."""


class LLMResponseError(RuntimeError):
    """Raised when the LLM returns no usable content (e.g. it hit the token cap)."""


def allow_uploads(enabled: bool) -> None:
    """Record the user's consent (--allow-llm-upload). Off by default."""
    global _upload_allowed
    _upload_allowed = bool(enabled)


def uploads_allowed() -> bool:
    return _upload_allowed


def ask(
    prompt: str,
    system: str = "",
    temperature: float = 0.1,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    response_format: dict | None = None,
) -> str:
    """
    Send one chat request to Groq and return the reply text.

    Raises:
        LLMUploadNotAllowed: the user did not pass --allow-llm-upload.
        ValueError:          GROQ_API_KEY is missing.
        LLMResponseError:    the reply was empty or truncated at the token cap.
    """
    if not _upload_allowed:
        raise LLMUploadNotAllowed(
            "Refusing to send data to Groq: re-run with --allow-llm-upload to consent."
        )

    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise ValueError("GROQ_API_KEY is not set in the .env file")

    max_tokens = max(1, min(int(max_tokens), MAX_TOKENS_CEILING))
    client = Groq(api_key=api_key, timeout=REQUEST_TIMEOUT_SECONDS, max_retries=MAX_RETRIES)

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    kwargs = {}
    if response_format is not None:
        kwargs["response_format"] = response_format
    if MODEL.startswith("openai/gpt-oss"):
        # Reasoning tokens count against max_completion_tokens; keep them small.
        kwargs["reasoning_effort"] = "low"

    response = client.chat.completions.create(
        model=MODEL,
        messages=messages,
        temperature=temperature,
        max_completion_tokens=max_tokens,
        timeout=REQUEST_TIMEOUT_SECONDS,
        **kwargs,
    )

    choice = response.choices[0]
    content = choice.message.content or ""
    if choice.finish_reason == "length":
        raise LLMResponseError(f"LLM reply was cut off at the {max_tokens}-token limit")
    if not content.strip():
        raise LLMResponseError("LLM returned an empty reply")
    return content
