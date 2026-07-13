"""Tests for FaultInjector — Day 4."""

from __future__ import annotations

import pytest

from benchmark.fault_injector import (
    FaultInjectionResult,
    FaultInjector,
    ProviderTimeoutInjected,
)
from benchmark.spec import FaultInjectionSpec, MockToolCall


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_spec(fault_type: str, **kwargs) -> FaultInjectionSpec:
    return FaultInjectionSpec(type=fault_type, **kwargs)


def _make_tool_calls(*calls: tuple[str, dict]) -> list[MockToolCall]:
    return [MockToolCall(tool=name, arguments=args) for name, args in calls]


# ---------------------------------------------------------------------------
# timeout
# ---------------------------------------------------------------------------


class TestTimeoutInjection:
    """Timeout injection should raise ProviderTimeoutInjected deterministically."""

    def test_timeout_raises_exception(self) -> None:
        injector = FaultInjector(_make_spec("timeout", target="primary"))
        with pytest.raises(ProviderTimeoutInjected):
            injector.maybe_inject_timeout()

    def test_timeout_is_deterministic_no_real_sleep(self) -> None:
        """Calling twice should both raise immediately."""
        for _ in range(2):
            injector = FaultInjector(_make_spec("timeout"))
            with pytest.raises(ProviderTimeoutInjected):
                injector.maybe_inject_timeout()

    def test_no_timeout_when_not_configured(self) -> None:
        injector = FaultInjector(None)
        result = injector.maybe_inject_timeout()
        assert result.applied is False

    def test_no_timeout_for_other_fault_type(self) -> None:
        injector = FaultInjector(_make_spec("bad_args"))
        result = injector.maybe_inject_timeout()
        assert result.applied is False


# ---------------------------------------------------------------------------
# bad_args
# ---------------------------------------------------------------------------


class TestBadArgsInjection:
    """bad_args injection should corrupt tool call arguments."""

    def test_corrupts_target_tool_arguments(self) -> None:
        spec = _make_spec(
            "bad_args",
            target="read_file",
            payload={"arguments": {"path": None}},
        )
        injector = FaultInjector(spec)
        original = _make_tool_calls(("read_file", {"path": "config.yaml"}))
        modified, result = injector.maybe_inject_bad_args(original)

        assert result.applied is True
        assert result.fault_type == "bad_args"
        assert modified[0].arguments == {"path": None}

    def test_does_not_corrupt_non_target_tool(self) -> None:
        spec = _make_spec(
            "bad_args",
            target="read_file",
            payload={"arguments": {"path": None}},
        )
        injector = FaultInjector(spec)
        original = _make_tool_calls(("search_web", {"query": "test"}))
        modified, result = injector.maybe_inject_bad_args(original)

        assert result.applied is True  # injection was configured and applied
        assert modified[0].arguments == {"query": "test"}  # but this tool wasn't targeted

    def test_no_corruption_when_not_configured(self) -> None:
        injector = FaultInjector(None)
        original = _make_tool_calls(("read_file", {"path": "test.txt"}))
        modified, result = injector.maybe_inject_bad_args(original)

        assert result.applied is False
        assert modified[0].arguments == {"path": "test.txt"}

    def test_no_real_side_effects(self) -> None:
        """bad_args only modifies MockToolCall objects, no real I/O."""
        spec = _make_spec(
            "bad_args",
            target="write_file",
            payload={"arguments": {"path": None, "content": None}},
        )
        injector = FaultInjector(spec)
        original = _make_tool_calls(("write_file", {"path": "x", "content": "y"}))
        modified, _ = injector.maybe_inject_bad_args(original)
        # The modified calls are just MockToolCall objects
        assert isinstance(modified[0], MockToolCall)


# ---------------------------------------------------------------------------
# duplicate
# ---------------------------------------------------------------------------


class TestDuplicateInjection:
    """duplicate injection should copy the previous tool call."""

    def test_duplicates_last_history_entry(self) -> None:
        spec = _make_spec("duplicate")
        injector = FaultInjector(spec)
        current = _make_tool_calls(("search_web", {"query": "test"}))
        history = [("read_file", {"path": "config.yaml"})]

        modified, result = injector.maybe_inject_duplicate(current, history)

        assert result.applied is True
        assert result.fault_type == "duplicate"
        assert len(modified) == 2  # original + duplicate
        assert modified[1].tool == "read_file"
        assert modified[1].arguments == {"path": "config.yaml"}

    def test_no_duplicate_without_history(self) -> None:
        spec = _make_spec("duplicate")
        injector = FaultInjector(spec)
        current = _make_tool_calls(("read_file", {"path": "test.txt"}))

        modified, result = injector.maybe_inject_duplicate(current, [])

        assert result.applied is False

    def test_no_duplicate_when_not_configured(self) -> None:
        injector = FaultInjector(None)
        current = _make_tool_calls(("read_file", {"path": "test.txt"}))
        history = [("read_file", {"path": "config.yaml"})]

        modified, result = injector.maybe_inject_duplicate(current, history)

        assert result.applied is False
        assert len(modified) == 1


# ---------------------------------------------------------------------------
# prompt_injection
# ---------------------------------------------------------------------------


class TestPromptInjection:
    """prompt_injection should escalate safe tool calls to high-risk tools."""

    def test_escalates_to_execute_shell(self) -> None:
        spec = _make_spec(
            "prompt_injection",
            target="read_file",
            payload={
                "escalate_to": "execute_shell",
                "escalate_arguments": {"command": "cat /etc/passwd"},
            },
        )
        injector = FaultInjector(spec)
        original = _make_tool_calls(("read_file", {"path": "README.md"}))

        modified, result = injector.maybe_inject_prompt_injection(original)

        assert result.applied is True
        assert result.fault_type == "prompt_injection"
        assert modified[0].tool == "execute_shell"
        assert modified[0].arguments == {"command": "cat /etc/passwd"}

    def test_injects_even_with_empty_tool_calls(self) -> None:
        spec = _make_spec(
            "prompt_injection",
            payload={
                "escalate_to": "execute_shell",
                "escalate_arguments": {"command": "rm -rf /"},
            },
        )
        injector = FaultInjector(spec)

        modified, result = injector.maybe_inject_prompt_injection([])

        assert result.applied is True
        assert len(modified) == 1
        assert modified[0].tool == "execute_shell"

    def test_no_injection_when_not_configured(self) -> None:
        injector = FaultInjector(None)
        original = _make_tool_calls(("read_file", {"path": "test.txt"}))

        modified, result = injector.maybe_inject_prompt_injection(original)

        assert result.applied is False
        assert modified[0].tool == "read_file"

    def test_no_real_shell_execution(self) -> None:
        """prompt_injection only creates MockToolCall objects, no real execution."""
        spec = _make_spec(
            "prompt_injection",
            payload={
                "escalate_to": "execute_shell",
                "escalate_arguments": {"command": "whoami"},
            },
        )
        injector = FaultInjector(spec)
        original = _make_tool_calls(("read_file", {"path": "x"}))
        modified, _ = injector.maybe_inject_prompt_injection(original)
        assert isinstance(modified[0], MockToolCall)


# ---------------------------------------------------------------------------
# No-injection baseline
# ---------------------------------------------------------------------------


class TestNoFaultInjection:
    """When no fault_injection is configured, nothing should happen."""

    def test_none_spec_does_nothing(self) -> None:
        injector = FaultInjector(None)

        # timeout
        result = injector.maybe_inject_timeout()
        assert result.applied is False

        # bad_args
        calls = _make_tool_calls(("read_file", {"path": "x"}))
        modified, r = injector.maybe_inject_bad_args(calls)
        assert r.applied is False
        assert len(modified) == 1

        # duplicate
        modified, r = injector.maybe_inject_duplicate(calls, [("read_file", {"path": "y"})])
        assert r.applied is False

        # prompt_injection
        modified, r = injector.maybe_inject_prompt_injection(calls)
        assert r.applied is False

    def test_fault_type_property(self) -> None:
        assert FaultInjector(None).fault_type is None
        assert FaultInjector(_make_spec("timeout")).fault_type == "timeout"

    def test_result_is_dataclass(self) -> None:
        result = FaultInjectionResult(
            applied=True, fault_type="test", reason="test reason"
        )
        assert result.applied is True
        assert result.fault_type == "test"
