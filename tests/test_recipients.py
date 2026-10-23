"""Tests for IntentLock recipient parsing, allowlists, and email validation."""

import pytest

from intentlock.policy import load_policy
from intentlock.validators import validate_arguments


EMAIL_POLICY_JSON = """{
    "version": 1,
    "task": "Email allowed recipients only",
    "allowed_tools": {
        "send_email": {
            "args": {
                "to": {
                    "type": "email_list",
                    "allowlist": ["me@example.com", "colleague@corp.internal"]
                },
                "subject": {
                    "type": "str",
                    "max_len": 100
                }
            }
        }
    }
}"""


@pytest.fixture
def email_tool():
    policy = load_policy(EMAIL_POLICY_JSON)
    return policy.allowed_tools["send_email"]


def test_allowed_recipient_single_string(email_tool):
    valid, reason = validate_arguments(email_tool, {
        "to": "me@example.com",
        "subject": "Hello"
    })
    assert valid is True
    assert reason == ""


def test_allowed_recipient_list(email_tool):
    valid, reason = validate_arguments(email_tool, {
        "to": ["me@example.com", "colleague@corp.internal"],
        "subject": "Hello team"
    })
    assert valid is True
    assert reason == ""


def test_allowed_recipient_comma_separated(email_tool):
    valid, reason = validate_arguments(email_tool, {
        "to": "me@example.com, colleague@corp.internal",
        "subject": "Hello all"
    })
    assert valid is True
    assert reason == ""


def test_non_allowlisted_address_denied(email_tool):
    secret_attacker = "hacker@evil.org"
    valid, reason = validate_arguments(email_tool, {
        "to": secret_attacker,
        "subject": "Data dump"
    })
    assert valid is False
    assert "one or more recipients not permitted" in reason
    # Generic denial: raw address must not be echoed
    assert secret_attacker not in reason


def test_mixture_allowed_and_disallowed_denied(email_tool):
    valid, reason = validate_arguments(email_tool, {
        "to": ["me@example.com", "untrusted@outside.org"],
        "subject": "Update"
    })
    assert valid is False
    assert "one or more recipients not permitted" in reason
    assert "untrusted@outside.org" not in reason


def test_comma_separated_with_disallowed_denied(email_tool):
    valid, reason = validate_arguments(email_tool, {
        "to": "me@example.com, untrusted@outside.org",
        "subject": "Update"
    })
    assert valid is False
    assert "one or more recipients not permitted" in reason


def test_display_name_tricks(email_tool):
    # Legitimate display name with allowed address -> allowed
    valid1, _ = validate_arguments(email_tool, {
        "to": "My Personal Account <me@example.com>",
        "subject": "Test"
    })
    assert valid1 is True

    # Quoted display name -> allowed
    valid2, _ = validate_arguments(email_tool, {
        "to": '"Colleague, Jane" <colleague@corp.internal>',
        "subject": "Test"
    })
    assert valid2 is True

    # Attacker puts allowed address in display name, but evil address in brackets -> MUST BE DENIED
    trick_address = "me@example.com <attacker@evil.com>"
    valid3, reason3 = validate_arguments(email_tool, {
        "to": trick_address,
        "subject": "Phish"
    })
    assert valid3 is False
    assert "one or more recipients not permitted" in reason3
    assert "attacker@evil.com" not in reason3


def test_lookalike_domain_suffix_denied(email_tool):
    lookalikes = [
        "me@example.com.attacker.com",
        "me@example.com.evil.io",
        "colleague@corp.internal.fake",
        "colleague@corp-internal.com",
    ]
    for target in lookalikes:
        valid, reason = validate_arguments(email_tool, {
            "to": target,
            "subject": "Spoof"
        })
        assert valid is False, f"Lookalike domain {target} was erroneously allowed!"
        assert "one or more recipients not permitted" in reason
        assert target not in reason


def test_uppercase_domain_normalization(email_tool):
    # Domain normalization: EXAMPLE.COM -> example.com (allowed)
    valid, reason = validate_arguments(email_tool, {
        "to": "me@EXAMPLE.COM",
        "subject": "Case test"
    })
    assert valid is True
    assert reason == ""

    # Local-part semantics are preserved (e.g. ME vs me, if different, but here domain is upper)
    valid2, reason2 = validate_arguments(email_tool, {
        "to": "colleague@CORP.INTERNAL",
        "subject": "Case test 2"
    })
    assert valid2 is True


def test_control_characters_rejected(email_tool):
    bad_inputs = [
        "me@example.com\nBcc: evil@attacker.com",
        "me@example.com\r\n",
        "me\0@example.com",
        "me\t@example.com",
        "colleague@corp.internal\x1b[31m",
    ]
    for bad in bad_inputs:
        valid, reason = validate_arguments(email_tool, {
            "to": bad,
            "subject": "Header injection attempt"
        })
        assert valid is False
        assert "control characters detected" in reason


def test_non_ascii_rejected(email_tool):
    non_ascii_inputs = [
        "më@example.com",
        "user@tëst.com",
        "用户@example.com",
    ]
    for bad in non_ascii_inputs:
        valid, reason = validate_arguments(email_tool, {
            "to": bad,
            "subject": "Non-ascii test"
        })
        assert valid is False
        assert "non-ASCII recipient addresses are not supported" in reason


def test_undeclared_cc_and_bcc_denied(email_tool):
    # Undeclared cc
    valid_cc, reason_cc = validate_arguments(email_tool, {
        "to": "me@example.com",
        "subject": "Test",
        "cc": "colleague@corp.internal"
    })
    assert valid_cc is False
    assert "cc/bcc fields not permitted" in reason_cc

    # Undeclared bcc
    valid_bcc, reason_bcc = validate_arguments(email_tool, {
        "to": "me@example.com",
        "subject": "Test",
        "bcc": "colleague@corp.internal"
    })
    assert valid_bcc is False
    assert "cc/bcc fields not permitted" in reason_bcc


def test_malformed_email_values(email_tool):
    malformed = [
        "",
        "   ",
        "not-an-email",
        "@example.com",
        "me@",
        "me@example@com",
        "me @example.com",
        "<>",
    ]
    for bad in malformed:
        valid, reason = validate_arguments(email_tool, {
            "to": bad,
            "subject": "Malformed"
        })
        assert valid is False
        assert "validation failed" in reason or "cannot be empty" in reason
