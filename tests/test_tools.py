"""Tests for fake tool system — Day 2 coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmark.spec import ToolRiskLevel
from benchmark.fake_tools import (
    FakeTool,
    ToolNotFoundError,
    ToolResult,
    get_tool,
    list_tools,
)


class TestToolRegistry:
    """Test tool registration and lookup."""

    def test_five_tools_registered(self) -> None:
        tools = list_tools()
        assert len(tools) == 5

    def test_all_tool_names(self) -> None:
        names = {t.name for t in list_tools()}
        assert names == {"read_file", "search_web", "write_file", "send_email", "execute_shell"}

    def test_get_tool_returns_fake_tool(self) -> None:
        tool = get_tool("read_file")
        assert isinstance(tool, FakeTool)
        assert tool.metadata.name == "read_file"

    def test_get_unknown_tool_raises(self) -> None:
        with pytest.raises(ToolNotFoundError, match="Tool 'nonexistent' not found"):
            get_tool("nonexistent")

    def test_list_tools_sorted(self) -> None:
        tools = list_tools()
        names = [t.name for t in tools]
        assert names == sorted(names)


class TestToolRiskLevels:
    """Verify each tool's risk level is correctly assigned."""

    @pytest.mark.parametrize(
        ("name", "expected_risk"),
        [
            ("read_file", ToolRiskLevel.safe),
            ("search_web", ToolRiskLevel.safe),
            ("write_file", ToolRiskLevel.high),
            ("send_email", ToolRiskLevel.high),
            ("execute_shell", ToolRiskLevel.critical),
        ],
    )
    def test_risk_level(self, name: str, expected_risk: ToolRiskLevel) -> None:
        tool = get_tool(name)
        assert tool.metadata.risk_level is expected_risk


class TestFakeToolExecution:
    """Verify fake tools return mock results without real side effects."""

    def test_read_file_returns_mock_content(self) -> None:
        tool = get_tool("read_file")
        result = tool.execute({"path": "/etc/passwd"})
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.tool == "read_file"
        output = result.output
        assert isinstance(output, str)
        assert "[mock]" in output
        # Must NOT actually read /etc/passwd
        assert "root:" not in output

    def test_search_web_returns_mock_results(self) -> None:
        tool = get_tool("search_web")
        result = tool.execute({"query": "python testing"})
        assert result.success is True
        output = result.output
        assert isinstance(output, str)
        assert "[mock]" in output

    def test_write_file_does_not_create_real_file(self) -> None:
        tool = get_tool("write_file")
        fake_path = "d:/this_should_not_exist_day2_test.txt"
        result = tool.execute({"path": fake_path, "content": "hello"})
        assert result.success is True
        output = result.output
        assert isinstance(output, str)
        assert "would_write" in output
        # The file must NOT actually exist
        assert not Path(fake_path).exists()

    def test_send_email_does_not_send(self) -> None:
        tool = get_tool("send_email")
        result = tool.execute({"to": "test@example.com", "subject": "hi"})
        assert result.success is True
        output = result.output
        assert isinstance(output, str)
        assert "would_send" in output

    def test_execute_shell_does_not_execute(self) -> None:
        tool = get_tool("execute_shell")
        result = tool.execute({"command": "rm -rf /"})
        assert result.success is True
        output = result.output
        assert isinstance(output, str)
        assert "would_execute" in output

    def test_tool_result_has_no_error_on_success(self) -> None:
        tool = get_tool("read_file")
        result = tool.execute({"path": "test.txt"})
        assert result.error is None
