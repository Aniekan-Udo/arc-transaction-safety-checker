"""
llm.py

Pluggable explanation backend.

analyzer.py never talks to a vendor SDK directly -- it goes through the narrow
`LLMProvider` protocol below, so the explanation model can be swapped (Claude,
Grok, Gemini, any OpenAI-compatible endpoint) by changing LLM_PROVIDER in .env,
with no change to the risk logic. Only the explanation layer is swappable by
design: decoding and scoring stay deterministic (see README, decision 1).

To add a provider:
  - OpenAI-compatible HTTP API -> add one entry to PROVIDERS.
  - Anything else -> add a class with a `complete()` method and a branch in
    get_provider().
"""

import os
from dataclasses import dataclass
from typing import Protocol

import anthropic
import requests
from dotenv import load_dotenv

load_dotenv()


class LLMError(RuntimeError):
    """The explanation provider was unreachable, misconfigured, or errored."""


class LLMProvider(Protocol):
    """One prompt in, one block of text out. Deliberately narrow."""

    name: str
    model: str

    def complete(self, prompt: str, max_tokens: int) -> str: ...


@dataclass(frozen=True)
class ProviderSpec:
    key_env: str
    default_model: str
    # base_url None means "not an OpenAI-compatible HTTP API" -- use the
    # provider's own SDK instead (currently only Anthropic).
    base_url: str | None = None
    # OpenAI's newer models renamed this parameter; other vendors kept max_tokens.
    token_param: str = "max_tokens"


# Default models were current when this was written -- check the vendor's docs
# before relying on one, or pin your own with LLM_MODEL in .env.
PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        key_env="ANTHROPIC_API_KEY",
        default_model="claude-opus-5",
    ),
    # Grok (xAI's own model) and Groq (a hosting provider for open models)
    # are different vendors despite the names -- keep both.
    "grok": ProviderSpec(
        key_env="XAI_API_KEY",
        default_model="grok-4",
        base_url="https://api.x.ai/v1",
    ),
    "groq": ProviderSpec(
        key_env="GROQ_API_KEY",
        default_model="openai/gpt-oss-120b",
        base_url="https://api.groq.com/openai/v1",
    ),
    "gemini": ProviderSpec(
        key_env="GEMINI_API_KEY",
        default_model="gemini-2.5-flash",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
    ),
    "openai": ProviderSpec(
        key_env="OPENAI_API_KEY",
        default_model="gpt-5",
        base_url="https://api.openai.com/v1",
        token_param="max_completion_tokens",
    ),
}


class AnthropicProvider:
    """Claude via the official SDK."""

    def __init__(self, model: str, api_key: str):
        self.name = "anthropic"
        self.model = model
        self._client = anthropic.Anthropic(api_key=api_key)

    def complete(self, prompt: str, max_tokens: int) -> str:
        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                # This is a short, mechanical rewording task -- no need to pay
                # for deep reasoning. Drop this if you pin a pre-4.6 model.
                output_config={"effort": "low"},
                messages=[{"role": "user", "content": prompt}],
            )
        except anthropic.AnthropicError as exc:
            raise LLMError(f"Anthropic request failed: {exc}") from exc

        # Thinking-capable models put a thinking block first, so don't assume
        # content[0] is the answer.
        return "".join(
            block.text for block in response.content if block.type == "text"
        ).strip()


class OpenAICompatibleProvider:
    """
    Any vendor exposing OpenAI's /chat/completions shape -- Grok, Gemini's
    compatibility endpoint, OpenAI itself, or a local server.
    """

    def __init__(self, name: str, model: str, api_key: str, spec: ProviderSpec):
        self.name = name
        self.model = model
        self._api_key = api_key
        self._spec = spec

    def complete(self, prompt: str, max_tokens: int) -> str:
        try:
            response = requests.post(
                f"{self._spec.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self._api_key}"},
                json={
                    "model": self.model,
                    self._spec.token_param: max_tokens,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]
        except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
            raise LLMError(f"{self.name} request failed: {exc}") from exc

        # Reasoning models can return a null content with the text in a
        # separate field, or spend the whole budget before answering.
        text = (message.get("content") or "").strip()
        if not text:
            raise LLMError(f"{self.name} returned an empty response")
        return text


def get_provider(name: str | None = None, model: str | None = None) -> LLMProvider:
    """
    Build the configured provider. Reads LLM_PROVIDER / LLM_MODEL from the
    environment unless overridden. Raises LLMError on misconfiguration --
    a missing key is a startup problem, not something to discover per-request.
    """
    name = (name or os.environ.get("LLM_PROVIDER") or "anthropic").lower()

    spec = PROVIDERS.get(name)
    if spec is None:
        raise LLMError(
            f"Unknown LLM_PROVIDER '{name}'. Options: {', '.join(PROVIDERS)}."
        )

    api_key = os.environ.get(spec.key_env, "")
    if not api_key:
        raise LLMError(f"LLM_PROVIDER is '{name}' but {spec.key_env} is not set.")

    model = model or os.environ.get("LLM_MODEL") or spec.default_model

    if spec.base_url is None:
        return AnthropicProvider(model=model, api_key=api_key)
    return OpenAICompatibleProvider(name=name, model=model, api_key=api_key, spec=spec)
