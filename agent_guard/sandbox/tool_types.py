"""
Minimal tool result type for AgentGuard SDK.

Separated from benchmark/fake_tools to keep the SDK dependency-free.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ToolResult:
    """Result of a tool execution."""

    tool: str
    success: bool
    output: Any | None = None
    error: str | None = None