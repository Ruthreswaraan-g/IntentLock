# IntentLock v0.1

> **Let AI act. Never let it exceed its authority.**

IntentLock is a lightweight, standard-library-only Python security library that sits between an AI agent and its execution tools. Before any tool is called, IntentLock verifies the proposed invocation against an explicit, task-scoped security policy and returns an **allow** or **deny** decision.

---

## 1. Project Purpose

AI agents typically operate with broad, per-tool permissions. When an agent reads untrusted content (such as incoming emails, tickets, or web pages), indirect prompt injection or unintended planning can cause the agent to invoke dangerous tools or exfiltrate private data to unauthorized destinations.

IntentLock solves this problem by enforcing a **task-specific least-privilege boundary**:
1. Permissions are granted per task rather than globally per tool.
2. Tools outside the policy are blocked by default.
3. Every argument is strictly validated for type, boundaries, and authorized recipients.
4. Function execution only occurs after authorization succeeds, using a defensive snapshot that is immune to argument tampering.

---

## 2. Currently Implemented Features (v0.1)

- **Zero-Dependency Core**: The core security engine (`intentlock`) depends strictly on the Python standard library.
- **Strict JSON Policy Parsing**:
  - Rejects duplicate JSON keys at all levels (preventing key-shadowing bypasses).
  - Rejects unknown top-level or tool-level keys.
  - Rejects wildcard permissions (`*` and `?`).
  - Rejects unsupported schema versions (only version `1` supported).
  - Loads policies into immutable, frozen dataclasses with `MappingProxyType`.
- **Default-Deny Tool Authorization**:
  - Tools absent from the active policy are blocked immediately.
  - Case-sensitive exact matching (e.g., `Read_inbox` does not match `read_inbox`).
  - Rejects empty, whitespace, or non-string tool names.
- **Strict Argument & Type Validation**:
  - Rejects undeclared arguments, explicitly including `cc` and `bcc`.
  - Rejects missing required arguments and `None` values.
  - **Type Confusion Protection**: Explicitly rejects `bool` where an `int` is required (overcoming Python's `isinstance(True, int) == True`).
  - Enforces numeric limits (`min`, `max`) and string length limits (`min_len`, `max_len`).
- **Robust Recipient Validation**:
  - Supports comma-separated recipient strings, single strings, and lists of addresses.
  - Correctly parses display-name formatting (`"Alice" <alice@example.com>`) and validates the actual mailbox address, defeating display-name confusion attacks.
  - Enforces exact email address matching against a strict allowlist (no substring or suffix matching).
  - Normalizes email domains to lowercase while preserving local-part semantics.
  - Detects and rejects control characters (`\r`, `\n`, `\0`, etc.) to block header injection.
  - Enforces ASCII-only recipient addresses in v0.1 to avoid Unicode homoglyph bypasses.
- **Defensive Guard API**:
  - `Guard.check(tool_name, arguments)`: Evaluates authorization with zero side effects.
  - `Guard.call(tool_name, tool_fn, **arguments)`: Executes the target tool function exactly once if authorized. Makes a defensive deep copy before validation to eliminate Time-of-Check to Time-of-Use (TOCTOU) and caller-mutation vulnerabilities.
- **Information Leakage Prevention**:
  - Denial reasons are strictly generic and never echo raw argument values, recipient addresses, or secret payloads.
- **Fail-Closed Architecture**:
  - Any unexpected parsing, validation, or internal exception results in a denial.

---

## 3. Threat Model Summary & Limitations

> [!IMPORTANT]
> **IntentLock reduces the blast radius of an over-permissioned agent by enforcing a per-task allowlist. It is experimental and is not a complete defense against prompt injection or data exfiltration.**

### In Scope
- Unauthorized tools proposed by a confused or compromised agent.
- Sending data to recipients not on the task allowlist.
- Display-name spoofing tricks (e.g., `me@example.com <attacker@evil.com>`).
- Undeclared `cc` or `bcc` parameters attempting covert exfiltration.
- Missing, malformed, or out-of-bounds argument values.
- Boolean-to-integer type confusion exploits.
- Argument mutation / TOCTOU attacks.
- Policy ambiguity (duplicate keys, wildcards, malformed schemas).

### Out of Scope & Known Limitations
- **Not a Prompt-Injection Detector**: IntentLock does not inspect or filter prompt text or LLM reasoning.
- **No Secret/DLP Content Scanning**: Email bodies or allowed outputs are not scanned for confidential data in v0.1.
- **Requires Guard Mediation**: The guard only protects tool calls that actually pass through it. Direct tool execution outside the guard bypasses all policies.
- **Non-ASCII Recipients**: Non-ASCII recipient addresses are rejected in v0.1.
- **Stateless Tool Calls**: v0.1 does not track cumulative session history across successive calls.

See [THREAT_MODEL.md](file:///C:/Users/RUTHRES/Documents/GitHub/Intentlock/THREAT_MODEL.md) for the complete threat model and security specifications.

---

## 4. Quickstart & Usage for Beginners

### Prerequisites
- Python 3.10+ (or [uv](https://astral.sh/uv))

### Running the Interactive Demo
The demo uses synthetic fake tools (`fake_read_inbox`, `fake_send_email`, `fake_delete_file`) that do not touch real networks, emails, files, or credentials.

Run using standard Python:
```bash
python examples/demo.py
```

Or using `uv`:
```bash
uv run python examples/demo.py
```

### Running the Automated Test Suite
The automated test suite contains 46 comprehensive unit, negative, and TOCTOU test cases.

Run using pytest:
```bash
pytest -v
```

Or using `uv`:
```bash
uv run --with pytest pytest -v
```

---

## 5. Code Example

```python
from intentlock import Guard, PermissionDenied

# 1. Load an immutable policy from JSON
guard = Guard.from_file("examples/policy.json")

# 2. Check an action without executing it (no side effects)
decision = guard.check("read_inbox", {"max_items": 10})
if decision.allowed:
    print("Action is authorized!")

# 3. Guard a real or simulated function call
def send_email(to: str, subject: str, body: str):
    print(f"Delivering email to {to}...")

try:
    guard.call(
        "send_email",
        send_email,
        to="me@example.com",
        subject="Project Status",
        body="All tests are passing."
    )
except PermissionDenied as err:
    print(f"Blocked by IntentLock: {err.reason}")
```

---

## 6. Future Work (Post-v0.1)

The following capabilities are planned for subsequent iterations and are **not** present in v0.1:
- **Session-Level Sensitivity Tracking (Taint Labels)**: Tracking sensitive data read by the agent across multiple steps to prevent exfiltration laundering.
- **Structured Redacted Audit Logging**: Tamper-resistant audit trails with automated secret redaction for regulatory compliance.
- **Agent Framework Integrations**: Native middleware for LangChain, LlamaIndex, AutoGen, and CrewAI.
- **Content Inspection Research**: Research into deterministic and zero-leakage content inspection filters for message payloads.
- **Policy Derivation**: Automated compilation of human intent into verified least-privilege policies.
