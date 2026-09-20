"""LLM client backed by LiteLLM — works with 100+ model providers.

Configure via (in priority order):
  1. ``rouge scan --model ... --api-key ... --api-base ...``
  2. Env vars: ROUGE_MODEL, ROUGE_API_KEY, ROUGE_API_BASE
  3. ``rouge setup`` (saves to ~/.rouge/config.json)
  4. Built-in default: Qwen Max on Qwen Cloud (DashScope) via DASHSCOPE_API_KEY

Model strings are LiteLLM format, e.g.:
  openai/qwen-max            (Qwen Cloud via DashScope, default)
  gpt-4o                     (OpenAI)
  claude-sonnet-4-5          (Anthropic)
  gemini/gemini-2.0-flash    (Google)
  groq/llama-3.3-70b-versatile
  ollama/llama3.1            (local)
"""

import os

# Use LiteLLM's bundled model cost map instead of fetching it from GitHub
# on every startup (slow / hangs offline).
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm

from .config import resolve_config, get_session_id

ROUGE_USER_AGENT = "rouge/0.3.0"

DEFAULT_MAX_TOKENS = 4096


def get_client(
    model: str | None = None,
    api_key: str | None = None,
    api_base: str | None = None,
) -> "LLMClient":
    return LiteLLMClient(model=model, api_key=api_key, api_base=api_base)


class LLMClient:
    async def generate(
        self,
        system_prompt: str,
        user_message: str,
        model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.3,
    ) -> str:
        raise NotImplementedError


class LiteLLMClient(LLMClient):
    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        api_base: str | None = None,
    ):
        cfg = resolve_config(model=model, api_key=api_key, api_base=api_base)
        self.model = cfg["model"]
        self.api_key = cfg["api_key"] or None
        self.api_base = cfg["api_base"] or None

    @property
    def name(self) -> str:
        return self.model

    async def generate(
        self,
        system_prompt: str,
        user_message: str,
        model: str | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        temperature: float = 0.3,
    ) -> str:
        kwargs: dict = {
            "model": model or self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if self.api_key:
            kwargs["api_key"] = self.api_key
        if self.api_base:
            kwargs["api_base"] = self.api_base
        # Coding-agent traffic headers (required by OpenCode Go, ignored by
        # everyone else): stable per-scan session id + own user agent.
        kwargs["extra_headers"] = {
            "x-opencode-session": get_session_id(),
            "User-Agent": ROUGE_USER_AGENT,
        }

        response = await litellm.acompletion(**kwargs)
        content = response.choices[0].message.content
        return content or ""
