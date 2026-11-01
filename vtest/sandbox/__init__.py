"""Sandbox images and assets for vtest (Containerfiles, entrypoint, k6 template)."""

from pathlib import Path

SANDBOX_DIR = Path(__file__).resolve().parent
K6_TEMPLATE_PATH = SANDBOX_DIR / "k6_template.js"
