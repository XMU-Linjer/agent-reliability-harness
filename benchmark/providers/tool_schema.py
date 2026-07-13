"""
Tool schema definitions for DeepSeek / OpenAI function-calling API.

Converts the internal tool registry into the JSON schema format
required by the chat completions API ``tools`` parameter.
"""

from __future__ import annotations

from typing import Any


# --- Tool schemas in OpenAI function-calling format ---

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file at the given path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to read.",
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file at the given path.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file to write.",
                    },
                    "content": {
                        "type": "string",
                        "description": "Content to write to the file.",
                    },
                },
                "required": ["path", "content"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_web",
            "description": "Fetch a specific HTTP/HTTPS URL or search for information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "Specific HTTP/HTTPS URL to fetch, for example https://httpbin.org/get.",
                    },
                    "query": {
                        "type": "string",
                        "description": "Optional search query string when no URL is available.",
                    },
                },
                "required": ["url"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email message.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {
                        "type": "string",
                        "description": "Recipient email address.",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Email subject line.",
                    },
                    "body": {
                        "type": "string",
                        "description": "Email body content.",
                    },
                },
                "required": ["to", "subject", "body"],
                "additionalProperties": False,
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_shell",
            "description": "Execute a shell command inside the configured sandbox only.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute.",
                    },
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        },
    },
]

# Index by name for selective retrieval
_SCHEMA_BY_NAME: dict[str, dict[str, Any]] = {
    s["function"]["name"]: s for s in TOOL_SCHEMAS
}


def get_tool_schemas(
    tool_names: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Return tool schemas for the specified tools.

    Args:
        tool_names: List of tool names to include. If None, returns all schemas.

    Returns:
        List of tool schema dicts in OpenAI function-calling format.
    """
    if tool_names is None:
        return list(TOOL_SCHEMAS)

    schemas = []
    for name in tool_names:
        if name in _SCHEMA_BY_NAME:
            schemas.append(_SCHEMA_BY_NAME[name])
    return schemas
