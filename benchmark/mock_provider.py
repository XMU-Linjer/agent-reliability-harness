"""
MockProviderAdapter — wraps the existing MockLLMProvider to implement
the unified LLMProvider protocol.

This preserves all existing offline/mock functionality while fitting into
the new provider abstraction.
"""

from __future__ import annotations

from typing import Any

from benchmark.mock_llm import MockLLMProvider
from benchmark.providers.base import LLMProvider, ProviderResponse
from benchmark.spec import MockResponse


class MockProviderAdapter:
    """Adapter that wraps MockLLMProvider to conform to LLMProvider protocol.

    The messages/tools parameters from ``chat()`` are ignored because mock
    responses are fully pre-configured.

    Args:
        mock_responses: Pre-configured mock responses to replay sequentially.
    """

    def __init__(self, mock_responses: list[MockResponse]) -> None:
        self._provider = MockLLMProvider(mock_responses)

    @property
    def total_calls(self) -> int:
        """Number of chat() calls made so far."""
        return self._provider.total_calls

    @property
    def remaining(self) -> int:
        """Number of responses still available."""
        return self._provider.remaining

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
    ) -> ProviderResponse:
        """Return the next pre-configured mock response.

        Args:
            messages: Ignored for mock provider.
            tools: Ignored for mock provider.

        Returns:
            ProviderResponse wrapping the next MockResponse.
        """
        mock_resp = self._provider.chat()
        return ProviderResponse(
            content=mock_resp.content,
            tool_calls=list(mock_resp.tool_calls),
            finish_reason=mock_resp.finish_reason,
            total_tokens=mock_resp.total_tokens,
            raw=None,
        )
