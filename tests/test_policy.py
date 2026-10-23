"""Tests for IntentLock policy parsing, validation, and immutability."""

import json
import pytest
from pathlib import Path

from intentlock.errors import PolicyError
from intentlock.policy import load_policy, load_policy_from_file, Policy


VALID_POLICY_JSON = json.dumps({
    "version": 1,
    "task": "Summarize my inbox and email the summary to me",
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


def test_valid_policy_loading():
    policy = load_policy(VALID_POLICY_JSON)
    assert policy.version == 1
    assert policy.task == "Summarize my inbox and email the summary to me"
    assert "read_inbox" in policy.allowed_tools
    assert "send_email" in policy.allowed_tools

    read_inbox = policy.allowed_tools["read_inbox"]
    assert "max_items" in read_inbox.args
    assert read_inbox.args["max_items"].arg_type == "int"
    assert read_inbox.args["max_items"].max_value == 50

    send_email = policy.allowed_tools["send_email"]
    assert send_email.args["to"].arg_type == "email_list"
    assert send_email.args["to"].allowlist == ("me@example.com",)
    assert send_email.args["subject"].max_len == 200
    assert send_email.args["body"].max_len == 5000


def test_policy_immutability():
    policy = load_policy(VALID_POLICY_JSON)

    # Top level frozen
    with pytest.raises((TypeError, AttributeError)):
        policy.version = 2  # type: ignore

    # Allowed tools mapping is immutable MappingProxyType
    with pytest.raises((TypeError, AttributeError)):
        policy.allowed_tools["new_tool"] = None  # type: ignore

    # Tool args mapping is immutable
    tool = policy.allowed_tools["read_inbox"]
    with pytest.raises((TypeError, AttributeError)):
        tool.args["extra_arg"] = None  # type: ignore

    # ArgPolicy frozen
    arg = tool.args["max_items"]
    with pytest.raises((TypeError, AttributeError)):
        arg.max_value = 100  # type: ignore


def test_missing_version():
    data = {
        "task": "Test task",
        "allowed_tools": {}
    }
    with pytest.raises(PolicyError, match="Missing required 'version'"):
        load_policy(json.dumps(data))


def test_unsupported_version():
    data = {
        "version": 2,
        "task": "Test task",
        "allowed_tools": {}
    }
    with pytest.raises(PolicyError, match="Unsupported policy version"):
        load_policy(json.dumps(data))


def test_version_not_integer_or_is_bool():
    # String version
    data = {"version": "1", "task": "T", "allowed_tools": {}}
    with pytest.raises(PolicyError, match="'version' must be an integer"):
        load_policy(json.dumps(data))

    # Boolean version (bool is subclass of int)
    data = {"version": True, "task": "T", "allowed_tools": {}}
    with pytest.raises(PolicyError, match="'version' must be an integer"):
        load_policy(json.dumps(data))


def test_unknown_top_level_keys():
    data = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {},
        "extra_field": "unexpected"
    }
    with pytest.raises(PolicyError, match="Unknown top-level key"):
        load_policy(json.dumps(data))


def test_duplicate_json_keys():
    raw_json = """{
        "version": 1,
        "task": "First task",
        "task": "Second task",
        "allowed_tools": {}
    }"""
    with pytest.raises(PolicyError, match="Duplicate JSON key detected"):
        load_policy(raw_json)

    # Nested duplicate keys
    raw_json_nested = """{
        "version": 1,
        "task": "Valid task",
        "allowed_tools": {
            "tool1": {
                "args": {
                    "arg1": {"type": "int", "max": 10},
                    "arg1": {"type": "int", "max": 20}
                }
            }
        }
    }"""
    with pytest.raises(PolicyError, match="Duplicate JSON key detected"):
        load_policy(raw_json_nested)


def test_non_dictionary_tool_configuration():
    # allowed_tools is a list
    data = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": ["read_inbox"]
    }
    with pytest.raises(PolicyError, match="'allowed_tools' must be a dictionary"):
        load_policy(json.dumps(data))

    # tool config is a string
    data2 = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {
            "read_inbox": "allow_all"
        }
    }
    with pytest.raises(PolicyError, match="Configuration for tool .* must be a dictionary"):
        load_policy(json.dumps(data2))


def test_unknown_validator_type():
    data = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {
            "my_tool": {
                "args": {
                    "foo": {"type": "regex", "pattern": ".*"}
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="Unknown validator type 'regex'"):
        load_policy(json.dumps(data))


def test_empty_required_recipient_allowlist():
    data = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {
            "send_email": {
                "args": {
                    "to": {
                        "type": "email_list",
                        "allowlist": []
                    }
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="'allowlist'.*cannot be empty"):
        load_policy(json.dumps(data))


def test_wildcard_values():
    # Wildcard in tool name
    data1 = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {
            "*": {"args": {}}
        }
    }
    with pytest.raises(PolicyError, match="Wildcard characters are forbidden"):
        load_policy(json.dumps(data1))

    # Wildcard in argument name
    data2 = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {
            "tool": {"args": {"*": {"type": "str"}}}
        }
    }
    with pytest.raises(PolicyError, match="Wildcard characters are forbidden"):
        load_policy(json.dumps(data2))

    # Wildcard in email allowlist
    data3 = {
        "version": 1,
        "task": "Test task",
        "allowed_tools": {
            "send_email": {
                "args": {
                    "to": {
                        "type": "email_list",
                        "allowlist": ["*@example.com"]
                    }
                }
            }
        }
    }
    with pytest.raises(PolicyError, match="Wildcard characters are forbidden"):
        load_policy(json.dumps(data3))


def test_malformed_json():
    with pytest.raises(PolicyError, match="Malformed JSON"):
        load_policy("{version: 1, broken json}")


def test_missing_policy_file(tmp_path: Path):
    non_existent = tmp_path / "does_not_exist.json"
    with pytest.raises(PolicyError, match="Policy file not found"):
        load_policy_from_file(non_existent)


def test_load_policy_from_file_success(tmp_path: Path):
    file_path = tmp_path / "policy.json"
    file_path.write_text(VALID_POLICY_JSON, encoding="utf-8")
    policy = load_policy_from_file(file_path)
    assert policy.version == 1
    assert "send_email" in policy.allowed_tools
