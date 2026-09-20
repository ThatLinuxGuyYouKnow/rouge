"""Central configuration for rouge's LLM provider.

Resolution order (highest to lowest priority):
  1. Explicit arguments (CLI flags like ``--model``)
  2. Environment variables: ROUGE_MODEL, ROUGE_API_KEY, ROUGE_API_BASE
  3. Config file: ~/.rouge/config.json (written by ``rouge setup``)
  4. Built-in default: Qwen (DashScope / Qwen Cloud)

Legacy: the old ROUGE_BACKEND=qwen env var maps to the default.
The old ``zen`` backend has been removed — ``rouge setup`` replaces it.
"""

import json
import os
import uuid
from pathlib import Path

CONFIG_DIR = Path.home() / ".rouge"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_MODEL = "openai/qwen-max"
DEFAULT_API_BASE = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"

# Model strings are LiteLLM format: "<provider>/<model>".
# "openai/<model>" + a custom api_base = any OpenAI-compatible endpoint.
PROVIDERS = {
    "qwen": {
        "label": "Qwen Cloud (DashScope / Alibaba Cloud)",
        "model": "openai/qwen-max",
        "api_base": DEFAULT_API_BASE,
        "key_env": "DASHSCOPE_API_KEY",
        "key_url": "https://dashscope.console.aliyun.com/apiKey",
        "needs_key": True,
    },
    "openai": {
        "label": "OpenAI",
        "model": "gpt-4o",
        "api_base": "",
        "key_env": "OPENAI_API_KEY",
        "key_url": "https://platform.openai.com/api-keys",
        "needs_key": True,
    },
    "anthropic": {
        "label": "Anthropic (Claude)",
        "model": "claude-sonnet-4-5",
        "api_base": "",
        "key_env": "ANTHROPIC_API_KEY",
        "key_url": "https://console.anthropic.com/",
        "needs_key": True,
    },
    "gemini": {
        "label": "Google Gemini",
        "model": "gemini/gemini-2.0-flash",
        "api_base": "",
        "key_env": "GEMINI_API_KEY",
        "key_url": "https://aistudio.google.com/apikey",
        "needs_key": True,
    },
    "groq": {
        "label": "Groq",
        "model": "groq/llama-3.3-70b-versatile",
        "api_base": "",
        "key_env": "GROQ_API_KEY",
        "key_url": "https://console.groq.com/keys",
        "needs_key": True,
    },
    "openrouter": {
        "label": "OpenRouter (any model)",
        "model": "openrouter/anthropic/claude-sonnet-4",
        "api_base": "",
        "key_env": "OPENROUTER_API_KEY",
        "key_url": "https://openrouter.ai/keys",
        "needs_key": True,
    },
    "ollama": {
        "label": "Ollama (local, no key needed)",
        "model": "ollama/llama3.1",
        "api_base": "http://localhost:11434",
        "key_env": "",
        "key_url": "",
        "needs_key": False,
    },
    "opencode": {
        "label": "OpenCode Go ($10/mo subscription — minimax-m3 + more)",
        "model": "anthropic/minimax-m3",
        # NOTE: the base intentionally omits the trailing "/v1" — LiteLLM's
        # Anthropic provider appends "/v1/messages" itself.
        "api_base": "https://opencode.ai/zen/go",
        "key_env": "OPENCODE_API_KEY",
        "key_url": "https://opencode.ai/auth",
        "needs_key": True,
        # Go requires coding-agent traffic headers (see
        # https://opencode.ai/docs/go/#where-can-i-use-it).
        "extra_headers": True,
    },
    "custom": {
        "label": "Custom (any LiteLLM model string + optional OpenAI-compatible URL)",
        "model": "",
        "api_base": "",
        "key_env": "",
        "key_url": "",
        "needs_key": False,
    },
}


def config_path() -> Path:
    return CONFIG_FILE


def load_config() -> dict:
    """Load the saved config file. Returns {} if none exists."""
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def save_config(model: str, api_key: str = "", api_base: str = "") -> Path:
    """Save config to ~/.rouge/config.json with owner-only permissions."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    data = {"model": model, "api_key": api_key, "api_base": api_base}
    # Write then chmod 0o600 so the API key is not world-readable.
    CONFIG_FILE.write_text(json.dumps(data, indent=2) + "\n")
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass
    return CONFIG_FILE


def clear_config() -> bool:
    """Delete the saved config file. Returns True if one existed."""
    try:
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()
            return True
    except OSError:
        pass
    return False


def resolve_config(
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
) -> dict:
    """Resolve the effective {model, api_key, api_base}.

    Precedence: explicit args > env vars > config file > built-in default.
    """
    saved = load_config()

    model = model or os.environ.get("ROUGE_MODEL") or saved.get("model") or ""
    api_key = api_key or os.environ.get("ROUGE_API_KEY") or saved.get("api_key") or ""
    api_base = api_base or os.environ.get("ROUGE_API_BASE") or saved.get("api_base") or ""

    # Legacy support: ROUGE_BACKEND=qwen means the old default.
    if not model:
        legacy = os.environ.get("ROUGE_BACKEND", "")
        if legacy == "zen":
            raise ValueError(
                "The 'zen' backend has been removed. Run `rouge setup` to "
                "configure any model provider (including Qwen Cloud)."
            )
        model, api_base = DEFAULT_MODEL, DEFAULT_API_BASE

    if not api_key and model == DEFAULT_MODEL:
        api_key = os.environ.get("DASHSCOPE_API_KEY", "")

    if model == DEFAULT_MODEL and not api_base:
        api_base = DEFAULT_API_BASE

    if not api_key and model == DEFAULT_MODEL:
        raise ValueError(
            "No API key configured for Qwen Cloud.\n"
            "  Run `rouge setup` (interactive), or set DASHSCOPE_API_KEY.\n"
            "  Get a key at https://dashscope.console.aliyun.com/apiKey"
        )

    # For non-default models, a missing key is fine — LiteLLM also reads
    # provider-native env vars (OPENAI_API_KEY, ANTHROPIC_API_KEY, ...).
    return {"model": model, "api_key": api_key, "api_base": api_base}


def current_model() -> str:
    """Return the resolved model name without requiring a key."""
    try:
        return resolve_config()["model"]
    except ValueError:
        return DEFAULT_MODEL


# Stable per-scan session id, sent as x-opencode-session (required by
# OpenCode Go for routing/prompt caching). One scan == one conversation:
# CLI scans set a fresh id per invocation; the monitor sets one per scan.
# Falls back to a single process-wide id so library use still sends *some*
# stable value instead of a fresh one per request.
_PROCESS_SESSION_ID = uuid.uuid4().hex


def get_session_id() -> str:
    return os.environ.get("ROUGE_SESSION") or _PROCESS_SESSION_ID


def new_session_id() -> str:
    sid = uuid.uuid4().hex
    os.environ["ROUGE_SESSION"] = sid
    return sid


def redact(key: str) -> str:
    """Redact an API key for display, keeping a recognizable tail."""
    if not key:
        return "(not set)"
    if len(key) <= 8:
        return "****"
    return f"{key[:3]}…{key[-4:]}"
