"""Tests for IntentLock argument validation and type safety."""

import math
import pytest

from intentlock.errors import PolicyError
from intentlock.policy import load_policy
from intentlock.validators import validate_arguments


POLICY_JSON = """{
    "version": 1,
    "task": "Test arguments",
    "allowed_tools": {
        "calculate": {
            "args": {
                "count": {
                    "type": "int",
                    "min": 1,
                    "max": 100
                },
                "label": {
                    "type": "str",
                    "min_len": 2,
                    "max_len": 10
                }
            }
        }
    }
}"""


@pytest.fixture
def calc_tool():
    policy = load_policy(POLICY_JSON)
    return policy.allowed_tools["calculate"]


def test_valid_arguments(calc_tool):
    valid, reason = validate_arguments(calc_tool, {"count": 5, "label": "valid"})
    assert valid is True
    assert reason == ""


def test_missing_required_arguments(calc_tool):
    valid, reason = validate_arguments(calc_tool, {"count": 5})
    assert valid is False
    assert "Missing required argument" in reason
    assert "label" in reason
    # Generic reason: does not reveal confidential data
    assert "5" not in reason


def test_extra_arguments(calc_tool):
    valid, reason = validate_arguments(calc_tool, {"count": 5, "label": "valid", "extra": "secret_data"})
    assert valid is False
    assert "Undeclared argument(s) rejected" in reason
    assert "extra" in reason
    # Ensure raw secret value is NEVER leaked in the reason
    assert "secret_data" not in reason


def test_arguments_cannot_be_none(calc_tool):
    valid, reason = validate_arguments(calc_tool, {"count": None, "label": "valid"})
    assert valid is False
    assert "cannot be None" in reason

    valid2, reason2 = validate_arguments(calc_tool, {"count": 5, "label": None})
    assert valid2 is False
    assert "cannot be None" in reason2


def test_bool_rejected_as_int(calc_tool):
    # In Python, True is an instance of int (issubclass(bool, int))
    valid, reason = validate_arguments(calc_tool, {"count": True, "label": "valid"})
    assert valid is False
    assert "expected int, got bool" in reason


def test_float_and_nan_rejected(calc_tool):
    valid, reason = validate_arguments(calc_tool, {"count": 5.5, "label": "valid"})
    assert valid is False
    assert "expected int, got float" in reason

    valid_nan, reason_nan = validate_arguments(calc_tool, {"count": float("nan"), "label": "valid"})
    assert valid_nan is False
    assert "expected int" in reason_nan


def test_int_bounds(calc_tool):
    # Below min (min=1)
    valid_low, reason_low = validate_arguments(calc_tool, {"count": 0, "label": "valid"})
    assert valid_low is False
    assert "below minimum allowed value" in reason_low
    assert "0" not in reason_low

    # Above max (max=100)
    valid_high, reason_high = validate_arguments(calc_tool, {"count": 101, "label": "valid"})
    assert valid_high is False
    assert "exceeds maximum allowed value" in reason_high
    assert "101" not in reason_high


def test_str_bounds(calc_tool):
    # Too short (min_len=2)
    valid_short, reason_short = validate_arguments(calc_tool, {"count": 10, "label": "a"})
    assert valid_short is False
    assert "below minimum required length" in reason_short

    # Too long (max_len=10)
    secret_str = "a" * 15
    valid_long, reason_long = validate_arguments(calc_tool, {"count": 10, "label": secret_str})
    assert valid_long is False
    assert "exceeds maximum allowed length" in reason_long
    # Ensure raw secret string is not in reason
    assert secret_str not in reason_long


def test_arguments_must_be_dict(calc_tool):
    valid, reason = validate_arguments(calc_tool, ["not", "a", "dict"])
    assert valid is False
    assert "Arguments must be passed as a dictionary" in reason


def test_fail_closed_on_unexpected_exception(calc_tool, monkeypatch):
    # Simulate an unexpected bug/error in internal validator
    def crashing_check(*args, **kwargs):
        raise RuntimeError("Unexpected internal crash!")

    monkeypatch.setattr("intentlock.validators._validate_int", crashing_check)
    valid, reason = validate_arguments(calc_tool, {"count": 5, "label": "valid"})
    assert valid is False
    assert "Authorization failed due to internal validator error" in reason
    assert "Unexpected internal crash!" not in reason
