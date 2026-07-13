"""
DeepSeekProvider — real LLM provider using the DeepSeek API.

Uses the OpenAI-compatible Python SDK (``openai`` package) with
DeepSeek's base URL. API key is read strictly from environment
variables or an optional ``.env.local`` file.

Security:
    - API key is NEVER logged, traced, printed, or written to reports.
    - Raw API responses are sanitised before storage.
"""

from __future__ import annotations

import os
from typing import Any

from benchmark.providers.base import ProviderResponse, ToolCall


class DeepSeekProviderError(Exception):
    """Raised when DeepSeek provider encounters a configuration or API error."""


class DeepSeekProvider:
    """LLM provider backed by the DeepSeek API.

    Args:
        api_key: The DeepSeek API key.
        model: Model identifier (default: ``deepseek-v4-flash``).
        base_url: DeepSeek API base URL.
        temperature: Sampling temperature.
        max_tokens: Maximum tokens to generate per request.
    """

    DEFAULT_BASE_URL = "https://api.deepseek.com"
    DEFAULT_MODEL = "deepseek-v4-flash"

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        temperature: float = 0.0,
        max_tokens: int = 4096,
    ) -> None:
        if not api_key or not api_key.strip():
            raise DeepSeekProviderError(
                "DEEPSEEK_API_KEY is required for provider=deepseek.\n"
                "Set it with:\n"
                '  PowerShell: $env:DEEPSEEK_API_KEY="sk-..."\n'
                '  Bash:       export DEEPSEEK_API_KEY="sk-..."'
            )
        self._api_key = api_key
        self._model = model
        self._base_url = base_url
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._client: Any = None

    def _get_client(self) -> Any:
        """Lazy-initialize the OpenAI client (avoids import at module level)."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise DeepSeekProviderError(
                    "The 'openai' package is required for DeepSeek provider.\n"
                    "Install it with: pip install openai>=1.0"
                ) from exc
            os.environ.pop("SSLKEYLOGFILE", None)
            self._client = OpenAI(
                api_key=self._api_key,
                base_url=self._base_url,
            )
        return self._client

    @classmethod
    def from_env(cls, model: str | None = None) -> DeepSeekProvider:
        """Create a DeepSeekProvider from environment variables.

        Reads ``DEEPSEEK_API_KEY`` from:
          1. Environment variable ``DEEPSEEK_API_KEY``
          2. Optional ``.env.local`` file (loaded via python-dotenv)

        Args:
            model: Override model identifier. Uses default if None.

        Returns:
            Configured DeepSeekProvider instance.

        Raises:
            DeepSeekProviderError: If no API key is available.
        """
        # Try loading .env.local (best-effort, no hard dependency)
        try:
            from dotenv import load_dotenv
            load_dotenv(".env.local", override=False)
        except ImportError:
            pass

        api_key = os.environ.get("DEEPSEEK_API_KEY", "")
        if not api_key:
            raise DeepSeekProviderError(
                "DEEPSEEK_API_KEY is required for provider=deepseek.\n"
                "Set it with:\n"
                '  PowerShell: $env:DEEPSEEK_API_KEY="sk-..."\n'
                '  Bash:       export DEEPSEEK_API_KEY="sk-..."'
            )

        return cls(
            api_key=api_key,
            model=model or cls.DEFAULT_MODEL,
        )

    @property
    def model(self) -> str:
        """The model identifier being used."""
        return self._model

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        """Send a chat completion request to DeepSeek.

        Args:
            messages: Conversation history in OpenAI-compatible format.
            tools: Optional list of tool schemas.

        Returns:
            ProviderResponse with content and/or tool_calls.

        Raises:
            DeepSeekProviderError: On API errors.
        """
        client = self._get_client()

        kwargs: dict[str, Any] = {
            "model": self._model,
            "messages": messages,
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        try:
            response = client.chat.completions.create(**kwargs)
        except Exception as exc:
            raise DeepSeekProviderError(
                f"DeepSeek API call failed: {exc}"
            ) from exc

        choice = response.choices[0]
        message = choice.message

        # Parse content
        content = message.content or ""

        # Parse tool_calls
        tool_calls: list[ToolCall] = []
        if message.tool_calls:
            for tc in message.tool_calls:
                import json
                try:
                    arguments = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    arguments = {"raw": tc.function.arguments}

                tool_calls.append(ToolCall(
                    tool=tc.function.name,
                    arguments=arguments if isinstance(arguments, dict) else {"raw": arguments},
                    call_id=tc.id,
                ))

        # Parse usage
        total_tokens = 0
        if response.usage:
            total_tokens = response.usage.total_tokens or 0

        # Build sanitised raw response (NO API KEY)
        raw = {
            "model": response.model,
            "finish_reason": choice.finish_reason,
            "usage": {
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": total_tokens,
            },
        }

        return ProviderResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason,
            total_tokens=total_tokens,
            raw=raw,
        )
