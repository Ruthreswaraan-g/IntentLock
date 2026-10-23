
# IntentLock
### Task-Scoped Authorization for AI-Agent Tool Calls

**IntentLock** is a security project exploring how task-specific authorization and information-flow checks can help constrain actions performed by AI agents.

AI agents can interact with tools, access information, and perform multi-step tasks. If their permissions are too broad, malicious instructions embedded in external content may influence actions beyond the user's original intent.

IntentLock aims to introduce a policy-enforcement layer between an AI agent and its tools, checking whether proposed actions are consistent with the current task's permissions.

## Problem Statement

Conventional tool-level permissions may not fully capture whether an action is appropriate for a particular task. A tool that is generally permitted could still be used with an unauthorized recipient, destination, or argument.

**Research question:** Can lightweight, task-scoped authorization combined with session-level information-flow tracking reduce unauthorized actions and data-exfiltration risks while preserving legitimate task completion?

## Proposed Approach

IntentLock explores four complementary mechanisms:

1. **Task-Scoped Policies** — Define which actions and tools are permitted for a particular task.
2. **Session-Level Sensitivity Tracking** — Track the sensitivity of information handled during a task.
3. **Argument and Destination Validation** — Check relevant tool-call arguments and destinations against the active policy.
4. **Audit Logging** — Record authorization decisions to support debugging and security analysis.

These mechanisms describe the intended architecture; they should not be interpreted as fully implemented features.

## Current Project Status

**Stage:** Initial development and proof-of-concept planning.

The repository will document the implementation as it develops. Features, test results, and performance measurements will be reported only after they have been implemented and verified.

## Planned Evaluation

The proposed evaluation will compare progressively stronger enforcement configurations:

- **Baseline:** Tool calls without the proposed enforcement layer.
- **Per-Tool Policy:** Check whether the requested tool is permitted.
- **Task-Scoped Policy:** Apply permissions specific to the current task.
- **Extended Enforcement:** Add session-level sensitivity tracking and argument/destination validation as these features become available.

Planned evaluation metrics include:

- Unauthorized-action blocking rate
- Legitimate task-completion rate
- False-block rate
- Authorization-check latency

No experimental results are claimed at this stage.

## Technology Stack

The implementation is planned around Python. Additional frameworks, libraries, and integrations will be documented once selected and used.

## Limitations

IntentLock is an experimental security project, not a complete or production-ready security solution.

Its effectiveness will depend on policy quality, enforcement coverage, accurate sensitivity tracking, and the ability to validate relevant tool arguments. Unmonitored execution paths, indirect information flows, compromised components, and covert channels may remain outside its protection.

## Roadmap

- [ ] Implement a basic task-specific policy checker
- [ ] Add automated unit tests
- [ ] Validate tool arguments and destinations
- [ ] Explore session-level information-flow tracking
- [ ] Add audit logging
- [ ] Integrate with a controlled AI-agent tool-execution path
- [ ] Evaluate security effectiveness, legitimate task completion, and latency
- [ ] Document experimental results and limitations

## Project Goal

The goal of IntentLock is to investigate a practical, testable approach to constraining AI-agent actions according to the user's intended task, rather than relying exclusively on broad tool permissions.

---

**Disclaimer:** IntentLock is under development. Proposed features and evaluation goals are not claims of completed implementation or demonstrated security effectiveness.
