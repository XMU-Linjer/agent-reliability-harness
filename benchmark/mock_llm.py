"""
MockLLMProvider for AgentReliabilityHarness.

Provides a deterministic, offline mock LLM that returns pre-configured
responses in sequence. No real API calls, no randomness.
"""

from __future__ import annotations

from benchmark.spec import MockResponse


class MockLLMResponseExhausted(Exception):
    """Raised when all pre-configured mock responses have been consumed."""


class MockLLMProvider:
    """A deterministic mock LLM provider that replays pre-configured responses.

    Args:
        responses: Ordered list of MockResponse objects to return sequentially.
    """

    def __init__(self, responses: list[MockResponse]) -> None:
        self._responses = list(responses)
        self._cursor = 0

    @property
    def total_calls(self) -> int:
        """Number of chat() calls made so far."""
        return self._cursor

    @property
    def remaining(self) -> int:
        """Number of responses still available."""
        return len(self._responses) - self._cursor

    def chat(self) -> MockResponse:
        """Return the next pre-configured response.

        Returns:
            The next MockResponse in sequence.

        Raises:
            MockLLMResponseExhausted: If all responses have been consumed.
        """
        if self._cursor >= len(self._responses):
            raise MockLLMResponseExhausted(
                f"All {len(self._responses)} mock responses have been consumed "
                f"after {self._cursor} calls. Add more mock_responses to the scenario."
            )
        response = self._responses[self._cursor]
        self._cursor += 1
        return response
