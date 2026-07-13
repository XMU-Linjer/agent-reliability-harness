"""
Tests for RemoteMcpSandboxToolExecutor.

Tests configuration validation and error handling.
No real MCP sandbox is required.
"""

import os

import pytest

from agent_guard.sandbox.remote_mcp_executor import (
    McpSandboxError,
    RemoteMcpSandboxToolExecutor,
)


class TestMcpConfig:
    """Test MCP sandbox configuration."""

    def test_missing_url_raises(self) -> None:
        with pytest.raises(McpSandboxError, match="MCP_SANDBOX_URL"):
            RemoteMcpSandboxToolExecutor(sandbox_url="", sandbox_token="token")

    def test_missing_token_raises(self) -> None:
        with pytest.raises(McpSandboxError, match="MCP_SANDBOX_TOKEN"):
            RemoteMcpSandboxToolExecutor(sandbox_url="https://sandbox.example.com", sandbox_token="")

    def test_from_env_missing_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("MCP_SANDBOX_URL", raising=False)
        monkeypatch.delenv("MCP_SANDBOX_TOKEN", raising=False)
        with pytest.raises(McpSandboxError, match="MCP_SANDBOX_URL"):
            RemoteMcpSandboxToolExecutor.from_env()

    def test_from_env_missing_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MCP_SANDBOX_URL", "https://sandbox.example.com")
        monkeypatch.delenv("MCP_SANDBOX_TOKEN", raising=False)
        with pytest.raises(McpSandboxError, match="MCP_SANDBOX_TOKEN"):
            RemoteMcpSandboxToolExecutor.from_env()

    def test_valid_config(self) -> None:
        executor = RemoteMcpSandboxToolExecutor(
            sandbox_url="https://sandbox.example.com",
            sandbox_token="test-token",
        )
        assert executor is not None

    def test_unsupported_tool(self) -> None:
        executor = RemoteMcpSandboxToolExecutor(
            sandbox_url="https://sandbox.example.com",
            sandbox_token="test-token",
        )
        result = executor.execute("unknown_tool", {})
        assert not result.success
        assert "not supported" in str(result.error)

    def test_connection_error_handled(self) -> None:
        """Test that connection errors are caught and returned as ToolResult.error."""
        executor = RemoteMcpSandboxToolExecutor(
            sandbox_url="https://nonexistent-sandbox-12345.example.com",
            sandbox_token="test-token",
            timeout_seconds=2,
        )
        result = executor.execute("execute_shell", {"command": "echo hello"})
        assert not result.success
        assert result.error is not None
        assert "MCP request failed" in result.error
