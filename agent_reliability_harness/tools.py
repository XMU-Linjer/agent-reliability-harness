"""
Fake tool system for AgentReliabilityHarness.

All tools are simulated — no real file I/O, no network, no shell execution.
Each tool returns deterministic mock results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_reliability_harness.spec import ToolRiskLevel


@dataclass(frozen=True)
class ToolMetadata:
    """Metadata describing a fake tool's identity and risk profile."""

    name: str
    description: str
    risk_level: ToolRiskLevel
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolResult:
    """Result of a fake tool execution."""

    tool: str
    success: bool
    output: Any | None = None
    error: str | None = None


class FakeTool:
    """A simulated tool that produces mock results without real side effects."""

    def __init__(
        self,
        metadata: ToolMetadata,
        handler: Any = None,
    ) -> None:
        self.metadata = metadata
        self._handler = handler

    def execute(self, arguments: dict[str, Any]) -> ToolResult:
        """Execute the fake tool with the given arguments.

        Returns:
            ToolResult with mock output. Never produces real side effects.
        """
        if self._handler is not None:
            return self._handler(self.metadata.name, arguments)
        return ToolResult(
            tool=self.metadata.name,
            success=True,
            output=f"[mock] {self.metadata.name} executed with {arguments}",
        )


# ---------------------------------------------------------------------------
# Built-in fake tool handlers
# ---------------------------------------------------------------------------


def _handle_read_file(name: str, arguments: dict[str, Any]) -> ToolResult:
    path = arguments.get("path", "unknown")
    return ToolResult(
        tool=name,
        success=True,
        output=f"[mock] Content of {path}:\n# Mock file content\nkey: value\ndatabase:\n  host: localhost:5432\n  port: 5432",
    )


def _handle_search_web(name: str, arguments: dict[str, Any]) -> ToolResult:
    query = arguments.get("query", "unknown")
    return ToolResult(
        tool=name,
        success=True,
        output=f"[mock] Search results for '{query}':\n1. Result A - https://example.com/a\n2. Result B - https://example.com/b",
    )


def _handle_write_file(name: str, arguments: dict[str, Any]) -> ToolResult:
    path = arguments.get("path", "unknown")
    content = arguments.get("content", "")
    return ToolResult(
        tool=name,
        success=True,
        output=f"[mock] would_write: path={path}, content_length={len(str(content))}",
    )


def _handle_send_email(name: str, arguments: dict[str, Any]) -> ToolResult:
    to = arguments.get("to", "unknown")
    subject = arguments.get("subject", "no subject")
    return ToolResult(
        tool=name,
        success=True,
        output=f"[mock] would_send: to={to}, subject={subject}",
    )


def _handle_execute_shell(name: str, arguments: dict[str, Any]) -> ToolResult:
    command = arguments.get("command", "unknown")
    return ToolResult(
        tool=name,
        success=True,
        output=f"[mock] would_execute: command={command}",
    )


# ---------------------------------------------------------------------------
# Tool registry
# ---------------------------------------------------------------------------

_TOOL_REGISTRY: dict[str, FakeTool] = {}


def _register_builtin_tools() -> None:
    """Register the 5 built-in fake tools."""
    builtins = [
        FakeTool(
            metadata=ToolMetadata(
                name="read_file",
                description="Read the contents of a file",
                risk_level=ToolRiskLevel.safe,
                parameters={"path": "string"},
            ),
            handler=_handle_read_file,
        ),
        FakeTool(
            metadata=ToolMetadata(
                name="search_web",
                description="Search the web for information",
                risk_level=ToolRiskLevel.safe,
                parameters={"query": "string"},
            ),
            handler=_handle_search_web,
        ),
        FakeTool(
            metadata=ToolMetadata(
                name="write_file",
                description="Write content to a file",
                risk_level=ToolRiskLevel.high,
                parameters={"path": "string", "content": "string"},
            ),
            handler=_handle_write_file,
        ),
        FakeTool(
            metadata=ToolMetadata(
                name="send_email",
                description="Send an email message",
                risk_level=ToolRiskLevel.high,
                parameters={"to": "string", "subject": "string", "body": "string"},
            ),
            handler=_handle_send_email,
        ),
        FakeTool(
            metadata=ToolMetadata(
                name="execute_shell",
                description="Execute a shell command",
                risk_level=ToolRiskLevel.critical,
                parameters={"command": "string"},
            ),
            handler=_handle_execute_shell,
        ),
    ]
    for tool in builtins:
        _TOOL_REGISTRY[tool.metadata.name] = tool


# Initialize on import
_register_builtin_tools()


class ToolNotFoundError(Exception):
    """Raised when requesting a tool that is not registered."""


def get_tool(name: str) -> FakeTool:
    """Get a registered fake tool by name.

    Args:
        name: The tool name to look up.

    Returns:
        The corresponding FakeTool instance.

    Raises:
        ToolNotFoundError: If no tool with the given name is registered.
    """
    if name not in _TOOL_REGISTRY:
        available = ", ".join(sorted(_TOOL_REGISTRY.keys()))
        raise ToolNotFoundError(
            f"Tool '{name}' not found. Available tools: {available}"
        )
    return _TOOL_REGISTRY[name]


def list_tools() -> list[ToolMetadata]:
    """List metadata for all registered fake tools, sorted by name.

    Returns:
        Sorted list of ToolMetadata for all registered tools.
    """
    return [t.metadata for t in sorted(_TOOL_REGISTRY.values(), key=lambda t: t.metadata.name)]
