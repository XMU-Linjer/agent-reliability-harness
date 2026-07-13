"""
FailureClassifier for AgentGuard SDK.

The classifier is deterministic and uses trace event evidence only.
It does not read scenario_id or expected_failure to decide the result.
"""

from __future__ import annotations

from agent_guard.spec import EventType, FailureType
from agent_guard.trace.trace_logger import TraceEventRecord


class FailureClassifier:
    """Classify an agent run from its trace events."""

    def classify(self, events: list[TraceEventRecord]) -> FailureType:
        """Return the failure type supported by trace evidence.

        Args:
            events: List of TraceEventRecords from an agent run.

        Returns:
            FailureType enum value matching the evidence.
        """
        for ev in events:
            if ev.event_type == EventType.failure_classified:
                ft_value = ev.data.get("failure_type", "none")
                try:
                    return FailureType(ft_value)
                except ValueError:
                    pass

        for ev in events:
            if ev.event_type in (
                EventType.guard_decision,
                EventType.runtime_guard_decision,
            ):
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if check_type == "model" or reason in (
                    "hide_trace_request",
                    "trace_suppression_instruction",
                    "disallowed_model_switch",
                    "model_not_allowed",
                ) or "not in the allowed models" in reason:
                    return FailureType.policy_violation

        for ev in events:
            if ev.event_type in (
                EventType.guard_decision,
                EventType.runtime_guard_decision,
            ):
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if check_type == "budget" or "budget" in reason.lower():
                    return FailureType.budget_exceeded

        for ev in events:
            if ev.event_type == EventType.argument_guard_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if check_type in (
                    "invalid_arguments",
                    "arguments_not_object",
                    "missing_required_field",
                    "null_argument",
                    "argument_too_long",
                ):
                    return FailureType.invalid_arguments
                if check_type in (
                    "dangerous_delete_command",
                    "shell_sensitive_file_read",
                    "external_download_command",
                    "powershell_download_execute",
                    "dangerous_command",
                    "shell_command",
                    "command_download",
                ) or reason in (
                    "dangerous_delete_command",
                    "shell_sensitive_file_read",
                    "external_download_command",
                    "powershell_download_execute",
                    "dangerous_command",
                    "shell_command",
                    "command_download",
                ):
                    return FailureType.tool_blocked
                if check_type in (
                    "data_exfiltration_api_key",
                    "data_exfiltration_password",
                    "untrusted_recipient_domain",
                    "url_secret_exfiltration",
                    "data_exfiltration",
                    "ssrf_cloud_metadata",
                    "ssrf_localhost",
                    "ssrf_private_ip",
                    "ssrf_private_network",
                    "ssrf_link_local",
                ) or reason in (
                    "data_exfiltration_api_key",
                    "data_exfiltration_password",
                    "untrusted_recipient_domain",
                    "url_secret_exfiltration",
                    "data_exfiltration",
                    "ssrf_cloud_metadata",
                    "ssrf_localhost",
                    "ssrf_private_ip",
                    "ssrf_private_network",
                    "ssrf_link_local",
                ):
                    return FailureType.permission_denied
                if check_type in (
                    "path_traversal",
                    "sensitive_path",
                    "windows_sensitive_path",
                    "windows_system_write",
                    "linux_system_write",
                    "script_file_write",
                ):
                    return FailureType.permission_denied

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") == "deny" and ev.data.get("prompt_injection"):
                    return FailureType.prompt_injection

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                payload = str(ev.data.get("attack_payload", "")).lower()
                if check_type in (
                    "prompt_injection_tool_escalation",
                    "tool_escalation",
                    "ignore_policy",
                ) or reason in (
                    "prompt_injection_tool_escalation",
                    "tool_escalation",
                    "ignore_policy",
                ) or "ignore previous policy" in payload:
                    return FailureType.prompt_injection

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if check_type in ("tool_not_allowed", "denied_tool") or reason in (
                    "tool_not_allowed",
                    "denied_tool",
                ):
                    return FailureType.tool_blocked

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") != "deny":
                    continue
                if ev.data.get("check_type", "") == "firewall_allowed_tools":
                    return FailureType.permission_denied

        for ev in events:
            if ev.event_type == EventType.firewall_decision:
                if ev.data.get("action") != "deny":
                    continue
                check_type = ev.data.get("check_type", "")
                if check_type in (
                    "firewall_risk_level",
                    "firewall_denied_tools",
                    "firewall_unknown_tool",
                ):
                    return FailureType.tool_blocked

        for ev in events:
            if ev.event_type == EventType.fault_injected:
                if ev.data.get("fault_type", "") == "timeout":
                    return FailureType.provider_timeout

        for ev in events:
            if ev.event_type == EventType.tool_result:
                if ev.data.get("success", True):
                    continue
                error_msg = ev.data.get("error", "") or ev.error or ""
                if "invalid argument" in error_msg.lower():
                    return FailureType.invalid_arguments

        for ev in events:
            if ev.event_type == EventType.tool_execution_skipped:
                reason = ev.data.get("reason", "")
                if reason in (
                    "repeated_expensive_tool_call",
                    "duplicate_tool_execution",
                ):
                    return FailureType.duplicate_execution

        for ev in events:
            if ev.event_type == EventType.tool_call and ev.data.get("duplicate"):
                return FailureType.duplicate_execution

        for ev in events:
            if ev.event_type in (
                EventType.guard_decision,
                EventType.runtime_guard_decision,
            ):
                action = ev.data.get("action", "")
                check_type = ev.data.get("check_type", "")
                reason = ev.data.get("reason", "")
                if action == "deny" and (
                    check_type == "answer_verification"
                    or reason in ("missing_trace_evidence", "unverified_answer")
                ):
                    return FailureType.unverified_answer

        return FailureType.none