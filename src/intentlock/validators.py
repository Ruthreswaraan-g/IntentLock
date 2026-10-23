"""Argument and recipient validation logic for IntentLock.

All validation failure messages are strictly generic and never leak raw argument
values or secrets.
"""

from __future__ import annotations

import math
from typing import Any, Optional, Tuple

from .policy import ArgPolicy, ToolPolicy


def _is_int(val: Any) -> bool:
    """Check if value is an int and explicitly not a bool."""
    return isinstance(val, int) and not isinstance(val, bool)


def _validate_int(arg_name: str, val: Any, policy: ArgPolicy) -> Tuple[bool, str]:
    if isinstance(val, bool):
        return False, f"Argument {arg_name!r} type mismatch: expected int, got bool"
    if not isinstance(val, int):
        return False, f"Argument {arg_name!r} type mismatch: expected int, got {type(val).__name__}"

    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return False, f"Argument {arg_name!r} must be a finite integer"

    if policy.min_value is not None and val < policy.min_value:
        return False, f"Argument {arg_name!r} value is below minimum allowed value"
    if policy.max_value is not None and val > policy.max_value:
        return False, f"Argument {arg_name!r} value exceeds maximum allowed value"

    return True, ""


def _validate_str(arg_name: str, val: Any, policy: ArgPolicy) -> Tuple[bool, str]:
    if not isinstance(val, str):
        return False, f"Argument {arg_name!r} type mismatch: expected str, got {type(val).__name__}"

    if policy.min_len is not None and len(val) < policy.min_len:
        return False, f"Argument {arg_name!r} length is below minimum required length"
    if policy.max_len is not None and len(val) > policy.max_len:
        return False, f"Argument {arg_name!r} length exceeds maximum allowed length"

    return True, ""


def _split_recipient_tokens(raw: str) -> list[str]:
    """Split comma-separated recipient entries while respecting double quotes."""
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    escape = False

    for char in raw:
        if escape:
            current.append(char)
            escape = False
        elif char == '\\':
            current.append(char)
            escape = True
        elif char == '"':
            in_quotes = not in_quotes
            current.append(char)
        elif char == ',' and not in_quotes:
            tokens.append("".join(current).strip())
            current = []
        else:
            current.append(char)

    if in_quotes:
        # Unclosed quote is malformed
        return ["__MALFORMED_UNCLOSED_QUOTE__"]

    tail = "".join(current).strip()
    if tail:
        tokens.append(tail)
    return tokens


def _extract_address(token: str) -> Optional[str]:
    """Extract and validate the mailbox address from a single recipient token.

    Handles both bare addresses ('user@domain.com') and display-name formats
    ('User Name <user@domain.com>').
    Normalizes the domain part to lowercase.
    """
    token = token.strip()
    if not token or token == "__MALFORMED_UNCLOSED_QUOTE__":
        return None

    # Check for angle brackets: [display_name] <address>
    if "<" in token or ">" in token:
        if token.count("<") != 1 or token.count(">") != 1:
            return None
        start = token.find("<")
        end = token.find(">")
        if start >= end:
            return None
        # Ensure nothing non-whitespace follows the closing bracket
        if token[end + 1:].strip():
            return None
        addr = token[start + 1 : end].strip()
    else:
        addr = token

    # Email address validation rules:
    # 1. No whitespace within address
    if any(c.isspace() for c in addr):
        return None
    # 2. Exactly one '@'
    if addr.count("@") != 1:
        return None
    local_part, domain = addr.split("@")
    if not local_part or not domain:
        return None
    # 3. Domain format basic checks (no leading/trailing dots)
    if domain.startswith(".") or domain.endswith("."):
        return None
    # 4. Domain to lowercase, preserve local-part
    return f"{local_part}@{domain.lower()}"


def _validate_email_list(arg_name: str, val: Any, policy: ArgPolicy) -> Tuple[bool, str]:
    if val is None:
        return False, f"Argument {arg_name!r} cannot be None"

    raw_items: list[str] = []
    if isinstance(val, str):
        if not val.strip():
            return False, f"Argument {arg_name!r} cannot be empty"
        raw_items.append(val)
    elif isinstance(val, (list, tuple, set)):
        if len(val) == 0:
            return False, f"Argument {arg_name!r} cannot be empty"
        for item in val:
            if not isinstance(item, str):
                return False, f"Argument {arg_name!r} contains non-string item"
            if not item.strip():
                return False, f"Argument {arg_name!r} contains empty recipient"
            raw_items.append(item)
    else:
        return False, f"Argument {arg_name!r} type mismatch: expected email string or list of emails"

    # Step 1: Pre-parse checks for control characters and non-ASCII
    for raw in raw_items:
        if any(ord(c) < 32 or ord(c) == 127 for c in raw):
            return False, "Recipient validation failed: control characters detected"
        if not raw.isascii():
            return False, "Recipient validation failed: non-ASCII recipient addresses are not supported in v0.1"

    # Step 2: Split and parse all addresses handling display names and comma-separated lists
    allowlist = set(policy.allowlist or ())
    all_addresses: list[str] = []

    for raw in raw_items:
        tokens = _split_recipient_tokens(raw)
        if not tokens:
            return False, "Recipient validation failed: malformed recipient address"
        for token in tokens:
            addr = _extract_address(token)
            if addr is None:
                return False, "Recipient validation failed: malformed recipient address"
            all_addresses.append(addr)

    if not all_addresses:
        return False, "Recipient validation failed: no valid recipients found"

    # Step 3: Exact match against allowlist
    for addr in all_addresses:
        if addr not in allowlist:
            return False, "Recipient validation failed: one or more recipients not permitted by policy"

    return True, ""


def validate_arguments(tool_policy: ToolPolicy, arguments: Any) -> Tuple[bool, str]:
    """Validate arguments against tool policy.

    Fails closed on any unexpected exception.
    Denial reasons are generic and never reveal secrets or raw argument values.
    """
    try:
        if not isinstance(arguments, dict):
            return False, "Arguments must be passed as a dictionary"

        # Check for undeclared arguments (including cc/bcc)
        extra_keys = set(arguments.keys()) - set(tool_policy.args.keys())
        if extra_keys:
            if "cc" in extra_keys or "bcc" in extra_keys:
                return False, "Undeclared argument rejected (cc/bcc fields not permitted)"
            return False, f"Undeclared argument(s) rejected for tool {tool_policy.name!r}: {sorted(extra_keys)}"

        # Check for missing required arguments
        missing_keys = set(tool_policy.args.keys()) - set(arguments.keys())
        if missing_keys:
            return False, f"Missing required argument(s) for tool {tool_policy.name!r}: {sorted(missing_keys)}"

        # Validate each argument value
        for arg_name, arg_policy in tool_policy.args.items():
            val = arguments[arg_name]
            if val is None:
                return False, f"Argument {arg_name!r} cannot be None"

            if arg_policy.arg_type == "int":
                is_valid, reason = _validate_int(arg_name, val, arg_policy)
            elif arg_policy.arg_type == "str":
                is_valid, reason = _validate_str(arg_name, val, arg_policy)
            elif arg_policy.arg_type == "email_list":
                is_valid, reason = _validate_email_list(arg_name, val, arg_policy)
            else:
                return False, f"Unsupported validator type for argument {arg_name!r}"

            if not is_valid:
                return False, reason

        return True, ""

    except Exception:
        # Fail closed on any unexpected error during argument validation
        return False, "Authorization failed due to internal validator error"
