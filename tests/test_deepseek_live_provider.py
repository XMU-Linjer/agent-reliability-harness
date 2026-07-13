"""
Live tests for DeepSeekProvider.

These tests require DEEPSEEK_API_KEY to be set.
If it's not set, tests will FAIL (not skip) with a clear message.
"""

import os
from pathlib import Path

import pytest

from benchmark.providers.base import ProviderResponse
from benchmark.providers.deepseek_provider import (
    DeepSeekProvider,
    DeepSeekProviderError,
)
from benchmark.mock_provider import MockProviderAdapter
from benchmark.providers.tool_schema import get_tool_schemas
from benchmark.spec import AgentRunSpec, MockResponse


def require_deepseek_key() -> str:
    """Get DEEPSEEK_API_KEY or skip the test with a clear message."""
    key = os.environ.get("DEEPSEEK_API_KEY")
    if not key:
        pytest.skip(
            "DEEPSEEK_API_KEY is required for live DeepSeek tests.\n"
            "Set it with:\n"
            '  PowerShell: $env:DEEPSEEK_API_KEY="sk-..."\n'
            '  Bash:       export DEEPSEEK_API_KEY="sk-..."'
        )
    return key


# --- Provider factory tests (no API key needed) ---


class TestProviderFactory:
    """Test provider factory without requiring API keys."""

    def test_create_mock_provider(self) -> None:
        mock_responses = [MockResponse(content="hello", finish_reason="stop")]
        provider = MockProviderAdapter(mock_responses)
        assert isinstance(provider, MockProviderAdapter)

    def test_create_mock_provider_chat(self) -> None:
        mock_responses = [MockResponse(content="hello", finish_reason="stop")]
        provider = MockProviderAdapter(mock_responses)
        resp = provider.chat(messages=[{"role": "user", "content": "hi"}])
        assert isinstance(resp, ProviderResponse)
        assert resp.content == "hello"


class TestDeepSeekProviderConfig:
    """Test DeepSeek provider configuration (no API calls)."""

    def test_default_model_is_current_flash_model(self) -> None:
        assert DeepSeekProvider.DEFAULT_MODEL == "deepseek-v4-flash"

    def test_missing_key_raises(self) -> None:
        with pytest.raises(DeepSeekProviderError, match="DEEPSEEK_API_KEY"):
            DeepSeekProvider(api_key="", model="test")

    def test_blank_key_raises(self) -> None:
        with pytest.raises(DeepSeekProviderError, match="DEEPSEEK_API_KEY"):
            DeepSeekProvider(api_key="   ", model="test")

    def test_from_env_missing_raises(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(DeepSeekProviderError, match="DEEPSEEK_API_KEY"):
            DeepSeekProvider.from_env()


class TestToolSchemas:
    """Test tool schema generation."""

    def test_all_schemas(self) -> None:
        schemas = get_tool_schemas()
        assert len(schemas) == 5
        names = {s["function"]["name"] for s in schemas}
        assert names == {"read_file", "write_file", "search_web", "send_email", "execute_shell"}

    def test_filtered_schemas(self) -> None:
        schemas = get_tool_schemas(["read_file", "execute_shell"])
        assert len(schemas) == 2

    def test_empty_filter(self) -> None:
        schemas = get_tool_schemas([])
        assert len(schemas) == 0

    def test_search_web_schema_requires_url_for_fetch_demo(self) -> None:
        schema = get_tool_schemas(["search_web"])[0]
        params = schema["function"]["parameters"]
        assert params["required"] == ["url"]
        assert "url" in params["properties"]


class _FakeFunction:
    name = "read_file"
    arguments = '{"path": "test.txt"}'


class _FakeToolCall:
    id = "call_real_deepseek_id"
    function = _FakeFunction()


class _FakeMessage:
    content = ""
    tool_calls = [_FakeToolCall()]


class _FakeChoice:
    message = _FakeMessage()
    finish_reason = "tool_calls"


class _FakeUsage:
    prompt_tokens = 10
    completion_tokens = 3
    total_tokens = 13


class _FakeResponse:
    choices = [_FakeChoice()]
    usage = _FakeUsage()
    model = "deepseek-v4-flash"


class _FakeChatCompletions:
    def create(self, **kwargs: object) -> _FakeResponse:
        return _FakeResponse()


class _FakeChat:
    completions = _FakeChatCompletions()


class _FakeClient:
    chat = _FakeChat()


class TestDeepSeekToolCallParsing:
    """Test DeepSeek response normalisation without calling the real API."""

    def test_preserves_real_tool_call_id(self) -> None:
        provider = DeepSeekProvider(api_key="sk-test", model="deepseek-v4-flash")
        setattr(provider, "_client", _FakeClient())

        resp = provider.chat(
            messages=[{"role": "user", "content": "Read test.txt"}],
            tools=get_tool_schemas(["read_file"]),
        )

        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].tool == "read_file"
        assert resp.tool_calls[0].arguments == {"path": "test.txt"}
        assert resp.tool_calls[0].call_id == "call_real_deepseek_id"


# --- Live API tests (require DEEPSEEK_API_KEY) ---


class TestDeepSeekLive:
    """Live tests that call the real DeepSeek API."""

    def test_simple_chat_returns_content(self) -> None:
        key = require_deepseek_key()
        provider = DeepSeekProvider(api_key=key)
        resp = provider.chat(
            messages=[{"role": "user", "content": "Say hello in one word."}]
        )
        assert isinstance(resp, ProviderResponse)
        assert resp.content, "Expected non-empty content"
        assert resp.total_tokens > 0

    def test_usage_total_tokens(self) -> None:
        key = require_deepseek_key()
        provider = DeepSeekProvider(api_key=key)
        resp = provider.chat(
            messages=[{"role": "user", "content": "Reply with the word 'test'."}]
        )
        assert resp.total_tokens > 0
        assert resp.raw is not None
        assert "usage" in resp.raw

    def test_tool_call_normalised(self) -> None:
        key = require_deepseek_key()
        provider = DeepSeekProvider(api_key=key)
        tools = get_tool_schemas(["read_file"])
        resp = provider.chat(
            messages=[
                {"role": "user", "content": "Read the file 'test.txt'."}
            ],
            tools=tools,
        )
        assert isinstance(resp, ProviderResponse)
        # DeepSeek should produce a tool call for read_file
        assert resp.tool_calls, "Expected DeepSeek to produce a read_file tool call"
        tc = resp.tool_calls[0]
        assert tc.tool == "read_file"
        assert "path" in tc.arguments
        assert tc.call_id

    def test_trace_does_not_contain_api_key(self) -> None:
        """Verify that API key never appears in provider response."""
        key = require_deepseek_key()
        provider = DeepSeekProvider(api_key=key)
        resp = provider.chat(
            messages=[{"role": "user", "content": "Say hello."}]
        )
        # Check raw response doesn't contain the key
        import json
        raw_str = json.dumps(resp.raw) if resp.raw else ""
        assert key not in raw_str, "API key must not appear in raw response"
        assert key not in resp.content, "API key must not appear in content"
