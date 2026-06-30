"""Tests for TraceLogger — Day 5 coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_reliability_harness.spec import EventType
from agent_reliability_harness.trace_logger import TraceEventRecord, TraceLogger


@pytest.fixture()
def tmp_trace_path(tmp_path: Path) -> Path:
    return tmp_path / "test_trace.jsonl"


# ---------------------------------------------------------------------------
# TraceEventRecord
# ---------------------------------------------------------------------------


class TestTraceEventRecord:
    """Verify TraceEventRecord construction and serialisation."""

    def test_to_dict_returns_dict(self) -> None:
        ev = TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_start,
            module="runner",
            data={"key": "value"},
        )
        d = ev.to_dict()
        assert isinstance(d, dict)
        assert d["run_id"] == "r1"
        assert d["event_type"] == "agent_start"

    def test_to_dict_is_json_serialisable(self) -> None:
        ev = TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.llm_request,
            module="mock_llm",
        )
        raw = json.dumps(ev.to_dict())
        parsed = json.loads(raw)
        assert parsed["event_type"] == "llm_request"

    def test_timestamp_auto_set(self) -> None:
        ev = TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_end,
            module="runner",
        )
        assert ev.timestamp != ""
        assert "T" in ev.timestamp  # ISO-8601

    def test_error_defaults_to_none(self) -> None:
        ev = TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_start,
            module="runner",
        )
        assert ev.error is None


# ---------------------------------------------------------------------------
# TraceLogger — in-memory
# ---------------------------------------------------------------------------


class TestTraceLoggerMemory:
    """Verify in-memory event accumulation."""

    def test_log_appends_event(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        ev = TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_start,
            module="runner",
        )
        logger.log(ev)
        assert len(logger.events) == 1

    def test_events_property_returns_copy(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        ev = TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_start,
            module="runner",
        )
        logger.log(ev)
        events = logger.events
        events.clear()
        # Internal list should not be affected
        assert len(logger.events) == 1

    def test_multiple_events_maintain_order(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        types = [
            EventType.agent_start,
            EventType.llm_request,
            EventType.llm_response,
            EventType.tool_call,
            EventType.tool_result,
            EventType.agent_end,
        ]
        for i, et in enumerate(types):
            logger.log(TraceEventRecord(
                run_id="r1",
                scenario_id="s1",
                step=i,
                event_type=et,
                module="test",
            ))
        events = logger.events
        assert [e.event_type for e in events] == types


# ---------------------------------------------------------------------------
# TraceLogger — flush
# ---------------------------------------------------------------------------


class TestTraceLoggerFlush:
    """Verify JSONL file output."""

    def test_flush_creates_file(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        logger.log(TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_start,
            module="runner",
        ))
        result_path = logger.flush()
        assert result_path.exists()

    def test_flush_creates_parent_dirs(self, tmp_path: Path) -> None:
        deep_path = tmp_path / "a" / "b" / "c" / "trace.jsonl"
        logger = TraceLogger(deep_path)
        logger.log(TraceEventRecord(
            run_id="r1",
            scenario_id="s1",
            step=0,
            event_type=EventType.agent_start,
            module="runner",
        ))
        logger.flush()
        assert deep_path.exists()

    def test_jsonl_each_line_parseable(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        for i in range(5):
            logger.log(TraceEventRecord(
                run_id="r1",
                scenario_id="s1",
                step=i,
                event_type=EventType.llm_request,
                module="mock_llm",
                data={"step": i},
            ))
        logger.flush()

        with tmp_trace_path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        assert len(lines) == 5
        for line in lines:
            parsed = json.loads(line)
            assert "event_type" in parsed
            assert "run_id" in parsed

    def test_jsonl_preserves_order(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        types = [EventType.agent_start, EventType.llm_request, EventType.agent_end]
        for i, et in enumerate(types):
            logger.log(TraceEventRecord(
                run_id="r1",
                scenario_id="s1",
                step=i,
                event_type=et,
                module="test",
            ))
        logger.flush()

        with tmp_trace_path.open("r", encoding="utf-8") as f:
            parsed_types = [json.loads(line)["event_type"] for line in f]
        assert parsed_types == [et.value for et in types]

    def test_flush_empty_logger_creates_empty_file(self, tmp_trace_path: Path) -> None:
        logger = TraceLogger(tmp_trace_path)
        logger.flush()
        assert tmp_trace_path.exists()
        assert tmp_trace_path.read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# No database
# ---------------------------------------------------------------------------


class TestNoDatabase:
    """Ensure TraceLogger does not use a database."""

    def test_no_sqlite_import(self) -> None:
        import agent_reliability_harness.trace_logger as mod
        mod_file = mod.__file__
        assert mod_file is not None
        source = Path(mod_file).read_text(encoding="utf-8")
        assert "sqlite" not in source.lower()
        assert "database" not in source.lower()

    def test_no_sqlalchemy_import(self) -> None:
        import agent_reliability_harness.trace_logger as mod
        mod_file = mod.__file__
        assert mod_file is not None
        source = Path(mod_file).read_text(encoding="utf-8")
        assert "sqlalchemy" not in source.lower()
