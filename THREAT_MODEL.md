# IntentLock Threat Model (v0.1)

IntentLock is a small, deterministic Python security checkpoint designed to sit between an AI agent and its external tools. It enforces task-scoped allowlists on tool access and validates all proposed argument values prior to execution.

---

## 1. Security Philosophy & Assumptions

- **Untrusted Agent and Planner**: The agent, LLM, prompt context, and any external text read by the agent (such as emails, websites, or user comments) are treated as **untrusted**. An indirect prompt injection or hallucination may cause an agent to propose unauthorized actions.
- **Trusted Policy & Engine**: The task policy is considered trusted input authored by a human developer or a trusted upstream control plane. The IntentLock code and Python execution runtime are trusted.
- **Deterministic Checkpoint**: IntentLock does not use LLMs or heuristics to judge intent. It enforces explicit, deterministic constraints outside the model.
- **Fail-Closed & Default-Deny**: Any tool not explicitly declared in the policy is blocked. Any unhandled error during parsing or validation defaults to blocking execution.

---

## 2. In-Scope Threats

The v0.1 implementation is designed to mitigate the following specific threats:

1. **Unauthorized Tool Execution**:
   - A manipulated agent attempts to invoke tools outside the scope of the assigned task (e.g., executing `delete_file` or `export_database` during an inbox summarization task).
   - Tool names with altered casing (e.g., `Read_inbox`) or malformed identifiers are denied.
2. **Exfiltration via Disallowed Recipients**:
   - The agent attempts to send sensitive information to an external address or lookalike domain (e.g., `attacker@evil.com` or `me@example.com.evil.io`).
   - Display-name spoofing and tricks (e.g., `"me@example.com <attacker@evil.com>"`), where the actual envelope recipient differs from the displayed name.
   - Mixture of authorized and unauthorized recipients in comma-separated strings or lists.
3. **Undeclared Argument & Covert Channel Injection**:
   - The agent attempts to inject undeclared parameters, specifically `cc` or `bcc` fields, to exfiltrate data without modifying the primary recipient.
   - Any argument not declared in the task policy schema is strictly denied.
4. **Boundary & Limit Violations**:
   - Arguments exceed configured thresholds (e.g., integer `max` or string `max_len`), preventing large batch exfiltrations or buffer overflows.
   - Missing required arguments or `None` values where concrete values are required.
5. **Type Confusion & Coercion Exploits**:
   - Boolean values being accepted as integers (e.g., `True` passed for an integer argument, exploiting Python's `isinstance(True, int)`).
   - `NaN` or non-numeric float values passed into numeric validators.
6. **Time-of-Check to Time-of-Use (TOCTOU) / Argument Mutation**:
   - Modification of argument dictionaries or nested structures between the check step and tool execution. IntentLock makes a defensive deep copy before validation and passes only the validated snapshot to the tool function.
7. **Policy Tampering & Ambiguity**:
   - Malformed JSON, duplicate keys (which could shadow security rules in naive parsers), unknown keys, unsupported schema versions, empty allowlists, or wildcard expressions (`*`).
8. **Information Leakage via Errors**:
   - Error messages and denial reasons provide generic failure descriptions and never echo raw argument values, recipient addresses, or potential secret payloads.

---

## 3. Out-of-Scope Threats

The following threats are explicitly out of scope for v0.1:

- **Detecting or Preventing Prompt Injection**: IntentLock does not evaluate, sanitize, or filter prompt text or LLM internal reasoning.
- **Content Inspection / Secret Scanning**: IntentLock does not inspect email bodies, file contents, or tool arguments for private secrets (e.g., credentials or PII) if the action is otherwise authorized.
- **Compromised Tools, Host OS, or Runtime**: IntentLock cannot protect against malicious tool implementations, compromised Python environments, or kernel vulnerabilities.
- **Malicious Policy Authors**: An author with permission to write or modify policies can grant arbitrary tool permissions.
- **Direct Tool Bypass**: IntentLock only protects tool calls that pass through `Guard.call()` or `Guard.check()`. If an agent has direct execution access to tools without passing through the guard, IntentLock offers no protection.
- **Multi-Agent Orchestration & Network Egress**: IntentLock does not enforce OS-level network firewalls, process sandboxing, or multi-agent messaging controls.
- **Denial of Service & Side Channels**: Timing attacks, algorithmic complexity denial of service, and resource exhaustion are not prevented by v0.1.

---

## 4. Known Limitations & Documented Trade-offs

1. **Blast-Radius Reduction Only**: IntentLock reduces the blast radius of an over-permissioned agent by enforcing a strict per-task allowlist. It is an experimental defense-in-depth layer, **not a complete defense against prompt injection or data exfiltration**.
2. **Mediation Requirement**: The guard only protects tool calls that are routed through it. If an application developer allows an agent direct function references, the guard is bypassed.
3. **Non-ASCII Recipients**: In v0.1, recipient validation strictly enforces ASCII email addresses. Internationalized domain names (IDN / punycode) and non-ASCII local parts are rejected to prevent Unicode homoglyph attacks.
4. **Stateless Enforcement**: v0.1 evaluates each tool call in isolation against the static policy. It does not track cumulative data flow (e.g., reading a confidential file and later sending an email to an allowed recipient).

---

## 5. Future Work (Post-v0.1)

The following capabilities are explicitly planned for future releases and are **not** present in v0.1:
- **Session-Level Sensitivity Tracking (Taint Tracking)**: Propagating confidential sensitivity labels across tool execution history to prevent multi-step laundering.
- **Structured Redacted Audit Logging**: Tamper-evident logging of all authorization decisions with automated redaction of sensitive arguments.
- **Agent Framework Integrations**: Drop-in middleware for popular agent frameworks (LangChain, LlamaIndex, AutoGen, CrewAI).
- **Content Inspection Research**: Safe, localized data-loss prevention (DLP) filters for body text and outputs.
- **Policy Derivation & Least-Privilege Generation**: Automated policy derivation from user task prompts using formal verification and human-in-the-loop review.
