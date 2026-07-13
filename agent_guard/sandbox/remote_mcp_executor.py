"""
RemoteMcpSandboxToolExecutor — delegates tool execution to a remote
MCP sandbox via HTTP JSON API.

Config from env: MCP_SANDBOX_URL, MCP_SANDBOX_TOKEN.
Token is NEVER logged or traced.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

from agent_guard.sandbox.tool_types import ToolResult


class McpSandboxError(Exception):
    """MCP sandbox configuration or communication error."""


_MCP_ENDPOINTS: dict[str, str] = {
    "execute_shell": "run_shell",
    "read_file": "read_file",
    "write_file": "write_file",
    "search_web": "fetch_url",
    "send_email": "send_email",
}


class RemoteMcpSandboxToolExecutor:
    """Executes tools via remote MCP sandbox API."""

    def __init__(
        self, sandbox_url: str, sandbox_token: str,
        timeout_seconds: int = 30, max_output_bytes: int = 20_000,
    ) -> None:
        if not sandbox_url:
            raise McpSandboxError(
                "MCP_SANDBOX_URL is required for tool_executor=remote_mcp_sandbox.\n"
                'Set: $env:MCP_SANDBOX_URL="https://your-sandbox.example.com"'
            )
        if not sandbox_token:
            raise McpSandboxError(
                "MCP_SANDBOX_TOKEN is required for tool_executor=remote_mcp_sandbox.\n"
                'Set: $env:MCP_SANDBOX_TOKEN="your-token"'
            )
        self._url = sandbox_url.rstrip("/")
        self._token = sandbox_token
        self._timeout = timeout_seconds
        self._max_bytes = max_output_bytes

    @classmethod
    def from_env(cls, timeout_seconds: int = 30, max_output_bytes: int = 20_000) -> RemoteMcpSandboxToolExecutor:
        """Create from environment variables."""
        try:
            from dotenv import load_dotenv
            load_dotenv(".env.local", override=False)
        except ImportError:
            pass
        return cls(
            sandbox_url=os.environ.get("MCP_SANDBOX_URL", ""),
            sandbox_token=os.environ.get("MCP_SANDBOX_TOKEN", ""),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
        )

    def execute(self, tool: str, arguments: dict[str, Any]) -> ToolResult:
        ep = _MCP_ENDPOINTS.get(tool)
        if ep is None:
            return ToolResult(tool=tool, success=False, error=f"Tool '{tool}' not supported by MCP executor")

        url = f"{self._url}/tools/{ep}"
        body = self._build_body(tool, arguments)
        start = time.monotonic()
        try:
            data = self._post(url, body)
        except Exception as exc:
            return ToolResult(tool=tool, success=False, error=f"MCP request failed: {exc}")

        ms = int((time.monotonic() - start) * 1000)
        return self._parse(tool, data, ms)

    def _build_body(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if tool == "execute_shell":
            import shlex
            try:
                parts = shlex.split(args.get("command", ""))
            except ValueError:
                parts = [args.get("command", "")]
            return {"command": parts, "cwd": "/workspace", "timeout_seconds": self._timeout, "max_output_bytes": self._max_bytes}
        if tool == "read_file":
            return {"path": args.get("path", "")}
        if tool == "write_file":
            return {"path": args.get("path", ""), "content": args.get("content", "")}
        if tool == "search_web":
            return {"url": args.get("url") or args.get("query", ""), "timeout_seconds": self._timeout}
        return args

    def _post(self, url: str, body: dict[str, Any]) -> dict[str, Any]:
        try:
            import requests
            r = requests.post(url, json=body, headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}, timeout=self._timeout)
            r.raise_for_status()
            return r.json()
        except ImportError:
            import urllib.request, urllib.error
            data = json.dumps(body).encode()
            req = urllib.request.Request(url, data=data, headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                return json.loads(resp.read().decode())

    def _parse(self, tool: str, data: dict[str, Any], ms: int) -> ToolResult:
        success = data.get("success", False)
        error = data.get("error")
        output: Any = data.get("output") or data.get("stdout", "")
        if isinstance(output, str) and len(output) > self._max_bytes:
            output = output[:self._max_bytes] + "\n... [truncated]"
        if tool == "execute_shell":
            output = {"exit_code": data.get("exit_code", -1), "stdout": data.get("stdout", ""), "stderr": data.get("stderr", ""), "duration_ms": ms}
            if not error and data.get("exit_code", 0) != 0:
                error = data.get("stderr", "non-zero exit code")
        return ToolResult(tool=tool, success=success, output=output, error=error)
