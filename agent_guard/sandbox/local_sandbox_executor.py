"""
LocalSandboxToolExecutor — executes tools with real shell, file I/O,
and network access, but ONLY within a sandbox directory.

Security constraints:
    - All file operations confined to sandbox_root.
    - execute_shell uses subprocess.run with shell=False.
    - Dangerous commands are blocked via denylist.
    - Network requests are restricted to an allowlist.
    - localhost, cloud metadata, private IP ranges are blocked.
    - Timeout is always enforced.
    - Output is truncated to max_output_bytes.
"""

from __future__ import annotations

import ipaddress
import os
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agent_guard.sandbox.tool_types import ToolResult


# --- Deny lists ---

# Command prefixes/patterns that are always blocked
COMMAND_DENYLIST: list[str] = [
    "rm -rf /",
    "rm -rf /*",
    "del /s",
    "del /q",
    "format ",
    "shutdown",
    "powershell iwr",
    "powershell invoke-webrequest",
    "powershell wget",
    "| sh",
    "| bash",
    "| iex",
    "| powershell",
    "curl | sh",
    "curl | bash",
    "wget -O - | sh",
    "wget -O - | bash",
    "iwr | iex",
    "invoke-expression",
    "invoke-webrequest",
    "start-process",
    "remove-item -recurse",
    "rd /s",
    "rmdir /s",
    "mkfs",
    "dd if=",
    ":(){ :|:& };:",
    "env",
    "printenv",
    "set ",  # print env on Windows
    "cat /proc",
    "cat .env",
    "type .env",
]

# Network targets that are always blocked
BLOCKED_HOSTS: list[str] = [
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.internal",
]

BLOCKED_IP_NETWORKS: list[str] = [
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]

DEFAULT_NETWORK_ALLOWLIST: list[str] = [
    "example.com",
    "httpbin.org",
]


def _is_blocked_ip(host: str) -> bool:
    """Check if a hostname/IP falls in a blocked network range."""
    try:
        addr = ipaddress.ip_address(host)
        for net_str in BLOCKED_IP_NETWORKS:
            if addr in ipaddress.ip_network(net_str, strict=False):
                return True
    except ValueError:
        # Not a valid IP address — it's a hostname, check against blocked hosts
        pass
    return host.lower() in [h.lower() for h in BLOCKED_HOSTS]


def _is_allowed_url(url: str, allowlist: list[str]) -> tuple[bool, str]:
    """Check if a URL is allowed by the network allowlist.

    Returns:
        (allowed, reason) tuple.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not host:
        return False, f"Could not parse hostname from URL: {url}"

    if _is_blocked_ip(host):
        return False, f"Access to {host} is blocked (localhost/private/metadata)"

    # Check if host matches any allowlisted domain
    for allowed_domain in allowlist:
        if host == allowed_domain or host.endswith(f".{allowed_domain}"):
            return True, "allowed"

    return False, (
        f"Host '{host}' is not in network allowlist. "
        f"Allowed domains: {allowlist}"
    )


def _is_command_denied(command_str: str) -> tuple[bool, str]:
    """Check if a command string matches any denylist pattern."""
    cmd_lower = command_str.lower().strip()
    for pattern in COMMAND_DENYLIST:
        if pattern.lower() in cmd_lower:
            return True, f"Command blocked by denylist: contains '{pattern}'"
    return False, ""


def _safe_path(sandbox_root: Path, requested_path: str) -> tuple[bool, Path, str]:
    """Resolve a path and verify it's within the sandbox root.

    Returns:
        (safe, resolved_path, reason) tuple.
    """
    resolved = (sandbox_root / requested_path).resolve()
    sandbox_resolved = sandbox_root.resolve()
    try:
        resolved.relative_to(sandbox_resolved)
    except ValueError:
        return False, resolved, (
            f"Path '{requested_path}' resolves to '{resolved}' "
            f"which is outside sandbox root '{sandbox_resolved}'"
        )
    return True, resolved, "ok"


class LocalSandboxToolExecutor:
    """Executes tools with real I/O constrained to a sandbox directory.

    Args:
        sandbox_root: Root directory for all sandbox operations.
        timeout_seconds: Maximum execution time for shell commands.
        max_output_bytes: Maximum output size in bytes.
        network_allowlist: Domains allowed for network access.
        command_allowlist: If set, only these command prefixes are allowed.
    """

    def __init__(
        self,
        sandbox_root: str | Path,
        timeout_seconds: int = 10,
        max_output_bytes: int = 20_000,
        network_allowlist: list[str] | None = None,
        command_allowlist: list[str] | None = None,
    ) -> None:
        self._sandbox_root = Path(sandbox_root).resolve()
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._network_allowlist = network_allowlist or list(DEFAULT_NETWORK_ALLOWLIST)
        self._command_allowlist = command_allowlist

        # Ensure sandbox root exists
        self._sandbox_root.mkdir(parents=True, exist_ok=True)

    @property
    def sandbox_root(self) -> Path:
        """The sandbox root directory."""
        return self._sandbox_root

    def execute(self, tool: str, arguments: dict[str, Any]) -> ToolResult:
        """Execute a tool within the sandbox.

        Args:
            tool: Name of the tool to execute.
            arguments: Tool arguments.

        Returns:
            ToolResult with real execution results.
        """
        dispatch = {
            "read_file": self._execute_read_file,
            "write_file": self._execute_write_file,
            "execute_shell": self._execute_shell,
            "search_web": self._execute_search_web,
            "send_email": self._execute_send_email,
        }

        handler = dispatch.get(tool)
        if handler is None:
            return ToolResult(
                tool=tool,
                success=False,
                error=f"Tool '{tool}' is not supported by LocalSandboxToolExecutor",
            )

        try:
            return handler(arguments)
        except Exception as exc:
            return ToolResult(
                tool=tool,
                success=False,
                error=f"Execution error: {exc}",
            )

    def _execute_read_file(self, arguments: dict[str, Any]) -> ToolResult:
        """Read a file within the sandbox."""
        path = arguments.get("path", "")
        if not path:
            return ToolResult(tool="read_file", success=False, error="Missing 'path' argument")

        safe, resolved, reason = _safe_path(self._sandbox_root, path)
        if not safe:
            return ToolResult(tool="read_file", success=False, error=reason)

        if not resolved.exists():
            return ToolResult(
                tool="read_file", success=False,
                error=f"File not found: {path}",
            )

        content = resolved.read_text(encoding="utf-8", errors="replace")
        if len(content) > self._max_output_bytes:
            content = content[:self._max_output_bytes] + "\n... [truncated]"

        return ToolResult(tool="read_file", success=True, output=content)

    def _execute_write_file(self, arguments: dict[str, Any]) -> ToolResult:
        """Write a file within the sandbox."""
        path = arguments.get("path", "")
        content = arguments.get("content", "")
        if not path:
            return ToolResult(tool="write_file", success=False, error="Missing 'path' argument")

        safe, resolved, reason = _safe_path(self._sandbox_root, path)
        if not safe:
            return ToolResult(tool="write_file", success=False, error=reason)

        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(str(content), encoding="utf-8")

        return ToolResult(
            tool="write_file", success=True,
            output=f"Wrote {len(str(content))} bytes to {path}",
        )

    def _execute_shell(self, arguments: dict[str, Any]) -> ToolResult:
        """Execute a shell command in the sandbox."""
        command = arguments.get("command", "")
        if not command:
            return ToolResult(tool="execute_shell", success=False, error="Missing 'command' argument")

        # Denylist check
        denied, deny_reason = _is_command_denied(command)
        if denied:
            return ToolResult(tool="execute_shell", success=False, error=deny_reason)

        # Command allowlist check (if configured)
        if self._command_allowlist is not None:
            cmd_parts = command.strip().split()
            if cmd_parts:
                cmd_base = cmd_parts[0].lower()
                if cmd_base not in [a.lower() for a in self._command_allowlist]:
                    return ToolResult(
                        tool="execute_shell", success=False,
                        error=(
                            f"Command '{cmd_base}' is not in command allowlist. "
                            f"Allowed: {self._command_allowlist}"
                        ),
                    )

        # Split command safely (shell=False)
        try:
            cmd_parts = shlex.split(command)
        except ValueError as exc:
            return ToolResult(
                tool="execute_shell", success=False,
                error=f"Failed to parse command: {exc}",
            )

        if not cmd_parts:
            return ToolResult(tool="execute_shell", success=False, error="Empty command")

        start_time = time.monotonic()
        try:
            result = subprocess.run(
                cmd_parts,
                cwd=str(self._sandbox_root),
                capture_output=True,
                timeout=self._timeout_seconds,
                shell=False,
                text=True,
                env=_sanitised_env(),
            )
        except subprocess.TimeoutExpired:
            duration_ms = int((time.monotonic() - start_time) * 1000)
            return ToolResult(
                tool="execute_shell", success=False,
                error=f"Command timed out after {self._timeout_seconds}s",
            )
        except FileNotFoundError:
            return ToolResult(
                tool="execute_shell", success=False,
                error=f"Command not found: {cmd_parts[0]}",
            )

        duration_ms = int((time.monotonic() - start_time) * 1000)
        stdout = result.stdout[:self._max_output_bytes] if result.stdout else ""
        stderr = result.stderr[:self._max_output_bytes] if result.stderr else ""

        output = {
            "exit_code": result.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration_ms,
        }

        return ToolResult(
            tool="execute_shell",
            success=result.returncode == 0,
            output=output,
            error=stderr if result.returncode != 0 else None,
        )

    def _execute_search_web(self, arguments: dict[str, Any]) -> ToolResult:
        """Fetch a URL within the network allowlist."""
        url = arguments.get("url") or arguments.get("query", "")
        if not url:
            return ToolResult(tool="search_web", success=False, error="Missing 'url' or 'query' argument")

        # If it doesn't look like a URL, treat it as a mock search
        if not url.startswith(("http://", "https://")):
            return ToolResult(
                tool="search_web", success=True,
                output=f"[sandbox] Search not supported for non-URL queries: {url}",
            )

        # Network allowlist check
        allowed, reason = _is_allowed_url(url, self._network_allowlist)
        if not allowed:
            return ToolResult(tool="search_web", success=False, error=reason)

        try:
            import requests
            resp = requests.get(
                url,
                timeout=self._timeout_seconds,
                headers={"User-Agent": "AgentReliabilityHarness/0.1"},
            )
            body = resp.text[:self._max_output_bytes]
            return ToolResult(
                tool="search_web", success=True,
                output={
                    "status_code": resp.status_code,
                    "body": body,
                    "content_type": resp.headers.get("Content-Type", ""),
                },
            )
        except ImportError:
            # Fallback to urllib if requests not installed
            import urllib.request
            import urllib.error
            req = urllib.request.Request(url, headers={"User-Agent": "AgentReliabilityHarness/0.1"})
            try:
                with urllib.request.urlopen(req, timeout=self._timeout_seconds) as resp:
                    body = resp.read(self._max_output_bytes).decode("utf-8", errors="replace")
                    return ToolResult(
                        tool="search_web", success=True,
                        output={
                            "status_code": resp.status,
                            "body": body,
                            "content_type": resp.headers.get("Content-Type", ""),
                        },
                    )
            except urllib.error.URLError as exc:
                return ToolResult(tool="search_web", success=False, error=str(exc))
        except Exception as exc:
            return ToolResult(tool="search_web", success=False, error=str(exc))

    def _execute_send_email(self, arguments: dict[str, Any]) -> ToolResult:
        """send_email is always simulated even in local sandbox mode."""
        to = arguments.get("to", "unknown")
        subject = arguments.get("subject", "no subject")
        return ToolResult(
            tool="send_email", success=True,
            output=f"[sandbox-mock] would_send: to={to}, subject={subject}",
        )


def _sanitised_env() -> dict[str, str]:
    """Create a sanitised copy of environment variables for subprocess.

    Removes sensitive variables to prevent leaking secrets via shell commands.
    """
    env = dict(os.environ)
    sensitive_keys = [
        "DEEPSEEK_API_KEY",
        "MCP_SANDBOX_TOKEN",
        "MCP_SANDBOX_URL",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "AZURE_CLIENT_SECRET",
    ]
    for key in sensitive_keys:
        env.pop(key, None)
    return env
