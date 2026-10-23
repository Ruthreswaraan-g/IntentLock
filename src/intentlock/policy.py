"""Policy loading, parsing, and immutability for IntentLock."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

from .errors import PolicyError

SUPPORTED_VERSION = 1
ALLOWED_TOP_LEVEL_KEYS = {"version", "task", "allowed_tools"}
SUPPORTED_VALIDATOR_TYPES = {"int", "str", "email_list"}


@dataclass(frozen=True)
class ArgPolicy:
    """Immutable specification for a single tool argument."""
    name: str
    arg_type: str
    min_value: Optional[int] = None
    max_value: Optional[int] = None
    min_len: Optional[int] = None
    max_len: Optional[int] = None
    allowlist: Optional[Tuple[str, ...]] = None


@dataclass(frozen=True)
class ToolPolicy:
    """Immutable specification for an allowed tool."""
    name: str
    args: Mapping[str, ArgPolicy]


@dataclass(frozen=True)
class Policy:
    """Immutable top-level IntentLock policy."""
    version: int
    task: str
    allowed_tools: Mapping[str, ToolPolicy]


def _strict_pairs_hook(pairs: list[tuple[Any, Any]]) -> dict[str, Any]:
    """Object pairs hook that rejects duplicate keys in any JSON object."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str):
            raise PolicyError(f"JSON object key must be a string, got {type(key).__name__}")
        if key in result:
            raise PolicyError(f"Duplicate JSON key detected: {key!r}")
        result[key] = value
    return result


def _check_no_wildcards(val: str, field_desc: str) -> None:
    if "*" in val or "?" in val:
        raise PolicyError(f"Wildcard characters are forbidden in {field_desc}")


def _is_int(val: Any) -> bool:
    """Check if value is integer and explicitly NOT boolean."""
    return isinstance(val, int) and not isinstance(val, bool)


def _normalize_email_address(raw_email: str) -> str:
    """Basic validation and domain lowercasing for allowlist entries."""
    if not isinstance(raw_email, str):
        raise PolicyError("Allowlist entries must be strings")
    _check_no_wildcards(raw_email, "allowlist address")
    email = raw_email.strip()
    if not email:
        raise PolicyError("Allowlist address cannot be empty")
    if not email.isascii():
        raise PolicyError("Non-ASCII recipient addresses in allowlist are not supported")
    if any(ord(c) < 32 or ord(c) == 127 for c in email):
        raise PolicyError("Allowlist address contains control characters")

    # If format is "Name <addr@domain>", extract addr@domain
    if "<" in email and email.endswith(">"):
        start = email.find("<")
        email = email[start + 1 : -1].strip()

    if "@" not in email:
        raise PolicyError(f"Invalid email format in allowlist: missing '@'")
    parts = email.split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise PolicyError("Invalid email format in allowlist")
    local_part, domain = parts[0], parts[1]
    return f"{local_part}@{domain.lower()}"


def _validate_int_arg(arg_name: str, config: dict[str, Any]) -> ArgPolicy:
    allowed_keys = {"type", "max", "min"}
    unknown = set(config.keys()) - allowed_keys
    if unknown:
        raise PolicyError(f"Unknown key(s) in int argument {arg_name!r}: {sorted(unknown)}")

    min_val = None
    max_val = None
    if "min" in config:
        if not _is_int(config["min"]):
            raise PolicyError(f"'min' constraint on argument {arg_name!r} must be an integer (bool rejected)")
        min_val = config["min"]
    if "max" in config:
        if not _is_int(config["max"]):
            raise PolicyError(f"'max' constraint on argument {arg_name!r} must be an integer (bool rejected)")
        max_val = config["max"]

    if min_val is not None and max_val is not None and min_val > max_val:
        raise PolicyError(f"'min' cannot exceed 'max' on argument {arg_name!r}")

    return ArgPolicy(
        name=arg_name,
        arg_type="int",
        min_value=min_val,
        max_value=max_val,
    )


def _validate_str_arg(arg_name: str, config: dict[str, Any]) -> ArgPolicy:
    allowed_keys = {"type", "max_len", "min_len"}
    unknown = set(config.keys()) - allowed_keys
    if unknown:
        raise PolicyError(f"Unknown key(s) in str argument {arg_name!r}: {sorted(unknown)}")

    min_len = None
    max_len = None
    if "min_len" in config:
        if not _is_int(config["min_len"]) or config["min_len"] < 0:
            raise PolicyError(f"'min_len' constraint on argument {arg_name!r} must be a non-negative integer")
        min_len = config["min_len"]
    if "max_len" in config:
        if not _is_int(config["max_len"]) or config["max_len"] < 0:
            raise PolicyError(f"'max_len' constraint on argument {arg_name!r} must be a non-negative integer")
        max_len = config["max_len"]

    if min_len is not None and max_len is not None and min_len > max_len:
        raise PolicyError(f"'min_len' cannot exceed 'max_len' on argument {arg_name!r}")

    return ArgPolicy(
        name=arg_name,
        arg_type="str",
        min_len=min_len,
        max_len=max_len,
    )


def _validate_email_list_arg(arg_name: str, config: dict[str, Any]) -> ArgPolicy:
    allowed_keys = {"type", "allowlist"}
    unknown = set(config.keys()) - allowed_keys
    if unknown:
        raise PolicyError(f"Unknown key(s) in email_list argument {arg_name!r}: {sorted(unknown)}")

    if "allowlist" not in config:
        raise PolicyError(f"Missing required 'allowlist' in email_list argument {arg_name!r}")

    raw_allowlist = config["allowlist"]
    if not isinstance(raw_allowlist, list):
        raise PolicyError(f"'allowlist' in argument {arg_name!r} must be a list")

    if len(raw_allowlist) == 0:
        raise PolicyError(f"'allowlist' in argument {arg_name!r} cannot be empty")

    normalized_allowlist = []
    for entry in raw_allowlist:
        normalized_allowlist.append(_normalize_email_address(entry))

    return ArgPolicy(
        name=arg_name,
        arg_type="email_list",
        allowlist=tuple(normalized_allowlist),
    )


def load_policy(policy_json: str) -> Policy:
    """Parse and validate a policy from a JSON string strictly."""
    if not isinstance(policy_json, str):
        raise PolicyError("Policy JSON input must be a string")

    try:
        data = json.loads(policy_json, object_pairs_hook=_strict_pairs_hook)
    except json.JSONDecodeError as exc:
        raise PolicyError(f"Malformed JSON in policy: {exc.msg}") from exc

    if not isinstance(data, dict):
        raise PolicyError("Policy root must be a JSON object")

    unknown_keys = set(data.keys()) - ALLOWED_TOP_LEVEL_KEYS
    if unknown_keys:
        raise PolicyError(f"Unknown top-level key(s) in policy: {sorted(unknown_keys)}")

    # Version check
    if "version" not in data:
        raise PolicyError("Missing required 'version' field in policy")
    version = data["version"]
    if not _is_int(version):
        raise PolicyError("Policy 'version' must be an integer (bool rejected)")
    if version != SUPPORTED_VERSION:
        raise PolicyError(f"Unsupported policy version: {version}. Expected {SUPPORTED_VERSION}")

    # Task check
    if "task" not in data:
        raise PolicyError("Missing required 'task' field in policy")
    task = data["task"]
    if not isinstance(task, str) or not task.strip():
        raise PolicyError("Policy 'task' must be a non-empty string")
    _check_no_wildcards(task, "policy task")

    # Allowed tools check
    if "allowed_tools" not in data:
        raise PolicyError("Missing required 'allowed_tools' field in policy")
    raw_tools = data["allowed_tools"]
    if not isinstance(raw_tools, dict):
        raise PolicyError("Policy 'allowed_tools' must be a dictionary")

    tools_dict: dict[str, ToolPolicy] = {}
    for tool_name, tool_config in raw_tools.items():
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise PolicyError("Tool name must be a non-empty string")
        _check_no_wildcards(tool_name, "tool name")

        if not isinstance(tool_config, dict):
            raise PolicyError(f"Configuration for tool {tool_name!r} must be a dictionary")

        unknown_tool_keys = set(tool_config.keys()) - {"args"}
        if unknown_tool_keys:
            raise PolicyError(f"Unknown key(s) in tool {tool_name!r}: {sorted(unknown_tool_keys)}")

        args_dict: dict[str, ArgPolicy] = {}
        if "args" in tool_config:
            raw_args = tool_config["args"]
            if not isinstance(raw_args, dict):
                raise PolicyError(f"'args' for tool {tool_name!r} must be a dictionary")

            for arg_name, arg_config in raw_args.items():
                if not isinstance(arg_name, str) or not arg_name.strip():
                    raise PolicyError(f"Argument name in tool {tool_name!r} must be a non-empty string")
                _check_no_wildcards(arg_name, f"argument name in tool {tool_name!r}")

                if not isinstance(arg_config, dict):
                    raise PolicyError(f"Configuration for argument {arg_name!r} in tool {tool_name!r} must be a dictionary")

                if "type" not in arg_config:
                    raise PolicyError(f"Missing 'type' for argument {arg_name!r} in tool {tool_name!r}")

                arg_type = arg_config["type"]
                if arg_type not in SUPPORTED_VALIDATOR_TYPES:
                    raise PolicyError(f"Unknown validator type {arg_type!r} for argument {arg_name!r}")

                if arg_type == "int":
                    args_dict[arg_name] = _validate_int_arg(arg_name, arg_config)
                elif arg_type == "str":
                    args_dict[arg_name] = _validate_str_arg(arg_name, arg_config)
                elif arg_type == "email_list":
                    args_dict[arg_name] = _validate_email_list_arg(arg_name, arg_config)

        tools_dict[tool_name] = ToolPolicy(
            name=tool_name,
            args=MappingProxyType(args_dict),
        )

    return Policy(
        version=version,
        task=task,
        allowed_tools=MappingProxyType(tools_dict),
    )


def load_policy_from_file(path: str | Path) -> Policy:
    """Load and parse policy strictly from a file path."""
    policy_path = Path(path)
    if not policy_path.exists():
        raise PolicyError(f"Policy file not found: {path}")
    if not policy_path.is_file():
        raise PolicyError(f"Policy path is not a file: {path}")

    try:
        content = policy_path.read_text(encoding="utf-8")
    except Exception as exc:
        raise PolicyError(f"Failed to read policy file: {exc}") from exc

    return load_policy(content)
