"""IntentLock exception hierarchy.

All core errors inherit from IntentLockError.
"""

from typing import Optional


class IntentLockError(Exception):
    """Base exception for all IntentLock errors."""
    pass


class PolicyError(IntentLockError):
    """Raised when a policy is invalid, malformed, or violates policy schemas."""
    pass


class PermissionDenied(IntentLockError):
    """Raised when Guard.call() blocks an unauthorized or invalid tool call."""

    def __init__(self, reason: str, tool: Optional[str] = None):
        super().__init__(reason)
        self.reason = reason
        self.tool = tool
