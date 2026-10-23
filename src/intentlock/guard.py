"""Guard implementation for IntentLock.

Provides check() for side-effect-free evaluation and call() for safe execution.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from .errors import IntentLockError, PermissionDenied
from .policy import Policy, load_policy, load_policy_from_file
from .validators import validate_arguments


@dataclass(frozen=True)
class Decision:
    """Immutable result of an authorization check."""
    allowed: bool
    reason: str
    tool: str


class Guard:
    """Runtime authorization guard for AI agent tool execution."""

    def __init__(self, policy: Policy) -> None:
        if not isinstance(policy, Policy):
            raise TypeError("policy must be an instance of intentlock.policy.Policy")
        self._policy = policy

    @property
    def policy(self) -> Policy:
        return self._policy

    @classmethod
    def from_file(cls, path: str | Path) -> Guard:
        """Create a Guard by loading and strictly validating a policy file."""
        policy = load_policy_from_file(path)
        return cls(policy)

    @classmethod
    def from_json(cls, json_str: str) -> Guard:
        """Create a Guard from a JSON policy string."""
        policy = load_policy(json_str)
        return cls(policy)

    def check(self, tool_name: str, arguments: Optional[Mapping[str, Any]] = None) -> Decision:
        """Check if a tool call is authorized without executing it.

        This method has no side effects and never invokes any tool.
        """
        try:
            # Tool name validation (default deny, exact match, reject non-string or empty)
            if not isinstance(tool_name, str) or not tool_name.strip():
                return Decision(
                    allowed=False,
                    reason="Tool name must be a non-empty string",
                    tool=str(tool_name) if tool_name is not None else "",
                )

            if tool_name not in self._policy.allowed_tools:
                return Decision(
                    allowed=False,
                    reason=f"Tool {tool_name!r} is not permitted by policy",
                    tool=tool_name,
                )

            tool_policy = self._policy.allowed_tools[tool_name]
            args_to_validate = arguments if arguments is not None else {}

            is_valid, reason = validate_arguments(tool_policy, args_to_validate)
            if not is_valid:
                return Decision(
                    allowed=False,
                    reason=reason,
                    tool=tool_name,
                )

            return Decision(
                allowed=True,
                reason="Tool call authorized",
                tool=tool_name,
            )

        except Exception:
            # Fail closed on any unexpected error during check
            safe_tool = str(tool_name) if isinstance(tool_name, str) else "unknown"
            return Decision(
                allowed=False,
                reason="Authorization failed due to internal error",
                tool=safe_tool,
            )

    def call(self, tool_name: str, tool_fn: Callable[..., Any], **arguments: Any) -> Any:
        """Authorize and execute a tool function with defensive argument copying.

        Raises PermissionDenied if the call is not permitted.
        Executes tool_fn exactly once with the validated arguments on success.
        """
        if not callable(tool_fn):
            raise TypeError("tool_fn must be callable")

        # Defensive deep copy BEFORE validation to prevent TOCTOU and mutation attacks
        checked_args = copy.deepcopy(arguments)

        decision = self.check(tool_name, checked_args)
        if not decision.allowed:
            raise PermissionDenied(reason=decision.reason, tool=decision.tool)

        # Execute only after authorization succeeds, using the exact copy that was checked
        return tool_fn(**checked_args)
