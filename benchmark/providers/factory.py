"""
Provider factory — creates the appropriate LLM provider.

Only supports deepseek in the SDK. Mock provider is in benchmark/.
"""

from __future__ import annotations

from typing import Any

from benchmark.providers.base import LLMProvider, ProviderResponse
from benchmark.providers.deepseek_provider import DeepSeekProvider


def create_provider(agent_run: Any) -> DeepSeekProvider:
    """Create a DeepSeek provider from agent_run configuration.

    Args:
        agent_run: Agent execution parameters with model, provider fields.

    Returns:
        DeepSeekProvider instance.

    Raises:
        ValueError: If the provider type is not deepseek.
    """
    provider = getattr(agent_run, "provider", "deepseek")

    if provider == "deepseek":
        return DeepSeekProvider.from_env(model=agent_run.model)

    raise ValueError(
        f"Unknown provider '{provider}'. "
        f"Supported providers: deepseek (use benchmark for mock)"
    )