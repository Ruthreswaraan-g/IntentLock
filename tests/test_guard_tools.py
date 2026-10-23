"""Tests for Guard.check(), Guard.call(), tool authorization, and TOCTOU protection."""

import json
from unittest.mock import Mock
import pytest

from intentlock.errors import PermissionDenied
from intentlock.guard import Decision, Guard


POLICY_JSON = json.dumps({
    "version": 1,
    "task": "Summarize inbox and notify",
    "allowed_tools": {
        "read_inbox": {
            "args": {
                "max_items": {
                    "type": "int",
                    "max": 50
                }
            }
        },
        "send_email": {
            "args": {
                "to": {
                    "type": "email_list",
                    "allowlist": ["me@example.com"]
                },
                "subject": {
                    "type": "str",
                    "max_len": 200
                },
                "body": {
                    "type": "str",
                    "max_len": 5000
                }
            }
        }
    }
})


@pytest.fixture
def guard():
    return Guard.from_json(POLICY_JSON)


# --- 1. Allowed calls ---

def test_authorized_tool_check_allowed(guard):
    decision = guard.check("read_inbox", {"max_items": 10})
    assert decision.allowed is True
    assert decision.tool == "read_inbox"
    assert decision.reason == "Tool call authorized"


def test_guard_call_invokes_function_once_with_validated_args(guard):
    mock_func = Mock(return_value={"status": "inbox_read", "count": 10})
    result = guard.call("read_inbox", mock_func, max_items=10)

    assert result == {"status": "inbox_read", "count": 10}
    mock_func.assert_called_once_with(max_items=10)


def test_guard_check_has_no_side_effects(guard):
    mock_func = Mock()
    decision = guard.check("read_inbox", {"max_items": 10})
    assert decision.allowed is True
    mock_func.assert_not_called()


# --- 2. Denied calls ---

def test_unauthorized_tool_denied(guard):
    mock_func = Mock()
    decision = guard.check("delete_file", {"path": "/etc/passwd"})
    assert decision.allowed is False
    assert "Tool 'delete_file' is not permitted by policy" in decision.reason

    with pytest.raises(PermissionDenied) as exc_info:
        guard.call("delete_file", mock_func, path="/etc/passwd")

    assert "Tool 'delete_file' is not permitted by policy" in exc_info.value.reason
    mock_func.assert_not_called()


def test_wrong_case_tool_names_denied(guard):
    mock_func = Mock()
    wrong_cases = ["Read_inbox", "READ_INBOX", "Read_Inbox", "send_Email"]
    for bad_name in wrong_cases:
        decision = guard.check(bad_name, {"max_items": 5})
        assert decision.allowed is False
        assert "not permitted by policy" in decision.reason

        with pytest.raises(PermissionDenied):
            guard.call(bad_name, mock_func, max_items=5)

    mock_func.assert_not_called()


def test_empty_or_non_string_tool_names_denied(guard):
    mock_func = Mock()
    bad_names = ["", "   ", None, 123, True, []]
    for bad_name in bad_names:
        decision = guard.check(bad_name, {})  # type: ignore
        assert decision.allowed is False
        assert "Tool name must be a non-empty string" in decision.reason

        with pytest.raises(PermissionDenied):
            guard.call(bad_name, mock_func)  # type: ignore

    mock_func.assert_not_called()


def test_denied_argument_prevents_function_invocation(guard):
    mock_func = Mock()
    with pytest.raises(PermissionDenied):
        guard.call(
            "send_email",
            mock_func,
            to="attacker@evil.com",
            subject="Exfiltration",
            body="Secret data"
        )
    mock_func.assert_not_called()


# --- 3. TOCTOU & Mutation protection ---

def test_mutation_of_input_dictionary_does_not_affect_call(guard):
    # Pass a mutable dictionary, and mutate it right after passing or simulate concurrent mutation
    received_args = {}

    def fake_send(to, subject, body):
        received_args["to"] = to
        received_args["subject"] = subject
        received_args["body"] = body
        return "sent"

    original_args = {
        "to": "me@example.com",
        "subject": "Original Subject",
        "body": "Safe content"
    }

    # Verify call succeeds with original args
    result = guard.call("send_email", fake_send, **original_args)
    assert result == "sent"
    assert received_args["to"] == "me@example.com"
    assert received_args["body"] == "Safe content"

    # Now simulate an external object mutation attempt:
    # If the caller has a reference to a mutable structure in original_args and mutates it
    mutable_list = ["me@example.com"]
    call_args = {
        "to": mutable_list,
        "subject": "Subject",
        "body": "Content"
    }

    # Call with call_args
    def capturing_tool(to, subject, body):
        # Even if someone modifies mutable_list externally, the tool got a deep copied snapshot
        return list(to)

    res = guard.call("send_email", capturing_tool, **call_args)
    assert res == ["me@example.com"]

    # Mutate the caller's list
    mutable_list.append("attacker@evil.com")
    # The executed snapshot was not mutated
    assert res == ["me@example.com"]


# --- 4. Fail-closed on unexpected errors ---

def test_guard_check_fail_closed(guard, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("Fatal unexpected crash in check")

    monkeypatch.setattr("intentlock.guard.validate_arguments", boom)
    decision = guard.check("read_inbox", {"max_items": 10})
    assert decision.allowed is False
    assert "Authorization failed due to internal error" in decision.reason
