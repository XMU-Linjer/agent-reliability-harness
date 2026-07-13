"""
TraceLogger for AgentGuard SDK.

Records structured trace events to an in-memory list and flushes
them to a JSONL file. Each line is independently JSON-parseable.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_guard.spec import EventType


@dataclass
class TraceEventRecord:
    """A single trace event produced during agent execution.

    Attributes:
        run_id: Unique identifier for this execution run.
        scenario_id: The scenario that produced this event.
        step: The step number within the execution (0-based).
        event_type: Category of the event (agent_start, llm_request, etc.).
        module: The module that produced the event (runner, guard, firewall, etc.).
        data: Arbitrary event-specific payload.
        error: Error message, if any.
        timestamp: ISO-8601 timestamp of the event.
    """

    run_id: str
    scenario_id: str
    step: int
    event_type: EventType
    module: str
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        """Convert this record to a JSON-serialisable dict."""
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


class TraceLogger:
    """Accumulates TraceEventRecords in memory and writes them as JSONL.

    Usage::

        logger = TraceLogger("runs/test/trace.jsonl")
        logger.log(TraceEventRecord(...))
        logger.flush()  # writes all events to disk

    Args:
        output_path: File path for the JSONL output.
    """

    def __init__(self, output_path: str | Path) -> None:
        self._output_path = Path(output_path)
        self._events: list[TraceEventRecord] = []

    @property
    def events(self) -> list[TraceEventRecord]:
        """Return the current list of recorded events (read-only copy)."""
        return list(self._events)

    def log(self, event: TraceEventRecord) -> None:
        """Append an event to the in-memory list."""
        self._events.append(event)

    def flush(self) -> Path:
        """Write all accumulated events to the JSONL file.

        Creates parent directories as needed. Each line is a single
        JSON object that can be parsed independently with ``json.loads``.

        Returns:
            The Path to the written file.
        """
        self._output_path.parent.mkdir(parents=True, exist_ok=True)
        with self._output_path.open("w", encoding="utf-8") as f:
            for event in self._events:
                f.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")
        return self._output_path