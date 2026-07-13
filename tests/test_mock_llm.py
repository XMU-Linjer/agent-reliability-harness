"""Tests for MockLLMProvider — Day 2 coverage."""

from __future__ import annotations

import pytest

from benchmark.mock_llm import MockLLMProvider, MockLLMResponseExhausted
from benchmark.spec import MockResponse, MockToolCall


class TestMockLLMProvider:
    """Test MockLLMProvider sequential response replay."""

    def _make_responses(self, n: int = 3) -> list[MockResponse]:
        return [
            MockResponse(content=f"response_{i}", total_tokens=100 * (i + 1))
            for i in range(n)
        ]

    def test_returns_responses_in_order(self) -> None:
        responses = self._make_responses(3)
        provider = MockLLMProvider(responses)

        for i in range(3):
            r = provider.chat()
            assert r.content == f"response_{i}"

    def test_total_calls_increments(self) -> None:
        provider = MockLLMProvider(self._make_responses(2))
        assert provider.total_calls == 0
        provider.chat()
        assert provider.total_calls == 1
        provider.chat()
        assert provider.total_calls == 2

    def test_remaining_decrements(self) -> None:
        provider = MockLLMProvider(self._make_responses(2))
        assert provider.remaining == 2
        provider.chat()
        assert provider.remaining == 1
        provider.chat()
        assert provider.remaining == 0

    def test_exhausted_raises_exception(self) -> None:
        provider = MockLLMProvider(self._make_responses(1))
        provider.chat()
        with pytest.raises(MockLLMResponseExhausted, match="All 1 mock responses have been consumed"):
            provider.chat()

    def test_empty_responses_raises_immediately(self) -> None:
        provider = MockLLMProvider([])
        with pytest.raises(MockLLMResponseExhausted):
            provider.chat()

    def test_total_tokens_preserved(self) -> None:
        responses = self._make_responses(2)
        provider = MockLLMProvider(responses)
        r0 = provider.chat()
        assert r0.total_tokens == 100
        r1 = provider.chat()
        assert r1.total_tokens == 200

    def test_tool_calls_preserved(self) -> None:
        responses = [
            MockResponse(
                content="calling tool",
                tool_calls=[MockToolCall(tool="read_file", arguments={"path": "a.txt"})],
            ),
        ]
        provider = MockLLMProvider(responses)
        r = provider.chat()
        assert len(r.tool_calls) == 1
        assert r.tool_calls[0].tool == "read_file"

    def test_finish_reason_preserved(self) -> None:
        responses = [
            MockResponse(content="done", finish_reason="stop"),
        ]
        provider = MockLLMProvider(responses)
        r = provider.chat()
        assert r.finish_reason == "stop"
