"""LLM client abstraction.

PRAETOR is LLM-driven but never LLM-*dependent*: if no provider/key is available,
`make_client` returns None and the orchestrator falls back to a deterministic
planner. This keeps the whole tool runnable (and its tests hermetic) offline.
"""
from __future__ import annotations

import os
from typing import Optional, Protocol, runtime_checkable

from ..config import Settings


@runtime_checkable
class LLMClient(Protocol):
    name: str

    def complete(self, system: str, user: str) -> str:
        """Return the model's text completion for a system+user prompt."""
        ...


class OpenAIClient:
    name = "openai"

    def __init__(self, model: Optional[str] = None):
        import openai  # deferred; only imported when actually used

        self._client = openai.OpenAI()
        self.model = model or "gpt-4o-mini"

    def complete(self, system: str, user: str) -> str:
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            temperature=0.1,
        )
        return resp.choices[0].message.content or ""


class AnthropicClient:
    name = "anthropic"

    def __init__(self, model: Optional[str] = None):
        import anthropic  # deferred

        self._client = anthropic.Anthropic()
        self.model = model or "claude-3-5-sonnet-latest"

    def complete(self, system: str, user: str) -> str:
        resp = self._client.messages.create(
            model=self.model,
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        parts = [b.text for b in resp.content if getattr(b, "type", "") == "text"]
        return "\n".join(parts)


def make_client(settings: Settings) -> Optional[LLMClient]:
    """Best-effort client construction. Returns None -> deterministic mode.

    provider = auto -> Anthropic if ANTHROPIC_API_KEY, else OpenAI if OPENAI_API_KEY.
    Any import error or missing key yields None (never raises).
    """
    provider = (settings.llm_provider or "auto").lower()
    if provider in ("none", "deterministic", "off"):
        return None
    try:
        if provider in ("auto", "anthropic") and os.getenv("ANTHROPIC_API_KEY"):
            return AnthropicClient(settings.llm_model)
        if provider in ("auto", "openai") and os.getenv("OPENAI_API_KEY"):
            return OpenAIClient(settings.llm_model)
    except Exception:
        return None
    return None
