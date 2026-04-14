# QUIC Autopilot Mission

## Objective

Advance `C:\src\incursa\quic-dotnet` toward a **fully functional, honestly supportable, professionally presented managed QUIC implementation for .NET**.

The long-term target is:
- a real managed QUIC implementation with narrow claims only where runtime behavior and proof exist,
- a progressively broader supported subset that remains truthful,
- black-box interoperability confidence that grows from narrow lanes to broad coverage,
- and eventually a library that can compete strongly on correctness, behavior, and professionalism.

This mission is **not** to maximize churn or close random gaps.
This mission **is** to advance the repo through the major protocol and product milestones in the right order.

---

## Source of truth

Each turn, treat the following as the primary truth sources, in order:

1. **Current local repo state**
   - code in `src/`
   - tests in `tests/`
   - interop harness code in `src/Incursa.Quic.InteropHarness/`
2. **Canonical SpecTrace artifacts**
   - `specs/requirements/quic/SPEC-QUIC-CRT.json`
   - `specs/requirements/quic/SPEC-QUIC-API.json`
   - `specs/requirements/quic/SPEC-QUIC-INT.json`
   - `specs/requirements/quic/REQUIREMENT-GAPS.md`
   - `specs/architecture/quic/`
   - `specs/work-items/quic/`
   - `specs/verification/quic/`
3. **Design guidance**
   - `docs/design/quic-public-api.md`
   - `docs/design/quic-public-api-gap-matrix.md`
   - `docs/design/quic-interop-prep-plan.md`
4. **Generated evidence and attestation**
   - Workbench outputs
   - generated coverage / triage artifacts
   - quality summaries

Use generated evidence when helpful, but do **not** let generated summaries override actual runtime behavior and requirement-home proof.

---

## Operating principles

### 1. Truthfulness first
- Never turn trace-only or proof-only progress into a support claim.
- Never widen the public support story unless the runtime really earns it.
- Never treat interop harness plumbing as broad interop success.
- Never treat a client-side attempt path as success unless the success boundary is actually proven.

### 2. Prefer permanent seams
- Prefer narrow permanent architecture seams on the final design.
- Avoid temporary facades, fake success paths, placeholder APIs, or misleading support markers.
- If a slice cannot be landed honestly in one turn, land the smallest truthful prerequisite instead.

### 3. One bounded slice per turn
- Choose a single high-value bounded slice.
- Separate runtime/code work from proof/test work and from trace/design work.
- Do not mix unrelated cleanup into a protocol slice unless required for truthful delivery.

### 4. Keep the repo usable
- Run the most relevant checks for the slice.
- Keep the worktree clean enough to evaluate the next turn honestly.
- Commit useful completed work locally.
- If a failing test is only stale requirement-home drift, fix the test honestly and move on.
- If baseline drift outside the slice prevents honest evaluation, stabilize first.

### 5. Manual review is rare
Only stop for manual review when one of these is true:
- a human product or support boundary decision is genuinely required,
- the next honest move depends on external information not present in the repo,
- a larger architectural split is required and cannot be chosen safely from repo evidence,
- or the repo baseline is too unstable to judge progress honestly.

Before asking for manual review, do one broader repo-local investigation pass.

---

## Current strategic posture

Assume the repo already has:
- a **narrow managed QUIC core**,
- a **narrow supported public API floor**,
- narrow **stream / transfer / retry** lanes,
- a **resumption chain** through accepted abbreviated resumption success,
- and at least the early-data prerequisite family started.

Do **not** assume that means broad protocol completeness.
The repo still needs broader protocol breadth, broader interop breadth, and stronger product-quality signals.

---

## Priority ladder

When choosing the next turn, use this priority ladder.
Always prefer the **highest incomplete major milestone** that can be advanced honestly in one bounded turn.

### Priority 1. Major protocol completion
Advance the next incomplete major protocol family in order:
1. resumption completion
2. early-data / 0-RTT family
3. anti-replay family
4. positive key update

If a major protocol family is in progress, stay on it until:
- a real milestone is reached,
- a truthful blocker is found,
- or another prerequisite must be landed first.

### Priority 2. Stream / transfer parity
After the current highest-priority protocol family is blocked or complete, work on:
- broader stream-management parity,
- abort / close / release semantics,
- broader transfer behavior.

### Priority 3. Interop expansion
After protocol work or parity work unlocks it, expand black-box interop confidence:
- convert one unsupported interop lane at a time,
- prefer lanes unlocked by already-landed runtime behavior,
- maintain a narrow honest interop story.

### Priority 4. Trust / PKI breadth
Advance broader trust, certificate-path, and hostname validation only after the core protocol and interop path are not the bigger blockers.

### Priority 5. Diagnostics / qlog / observability
Keep diagnostics useful, but do not let this side track outrank missing core protocol behavior unless diagnostics are directly blocking truthful progress.

### Priority 6. Professionalization
Coverage, attestation hygiene, spec cleanup, and release polish matter, but they are a support track.
Do them when:
- a protocol family is between slices,
- the baseline is too noisy to continue honestly,
- or a narrow supported claim needs cleaner evidence.

---

## Milestone roadmap

Treat this as the standing roadmap.
Update your local reasoning from current repo state each turn, but use this order.

### M1. Narrow functional core
Goal:
- honest managed handshake floor
- honest narrow public API floor
- honest narrow stream / transfer / retry floors
- narrow interop harness viability

Exit condition:
- runtime behavior exists and is test-backed for the narrow core.

### M2. Resumption chain
Goal:
- ticket ownership
- detached handoff
- richer detached material
- PSK-capable ClientHello attempt
- accept/reject branch point
- accepted abbreviated success

Exit condition:
- accepted abbreviated path reaches the narrow handshake-complete boundary,
- rejected path falls back cleanly,
- early data still closed.

### M3. Early-data / 0-RTT family
Goal:
- honest dormant eligibility / prerequisite material
- first real 0-RTT attempt slice
- supporting proof of the attempt boundary

Exit condition:
- the repo can honestly attempt the first narrow 0-RTT path,
- without implying anti-replay or broad support.

### M4. Anti-replay family
Goal:
- the minimum honest replay controls and acceptance boundaries required to stop treating 0-RTT as a raw client-only trick.

Exit condition:
- the repo can state a narrow honest 0-RTT boundary with matching replay controls.

### M5. Key update
Goal:
- positive key update support,
- not just guard-only rejection behavior.

Exit condition:
- real positive path exists and is proven.

### M6. Stream / transfer parity
Goal:
- broader stream-management parity,
- broader abort / close / release semantics,
- broader transfer behavior.

Exit condition:
- the repo is no longer limited to the current narrow stream and transfer contract.

### M7. Interop expansion
Goal:
- move from a few named lanes to a growing matrix of black-box likely-pass lanes.

Exit condition:
- unsupported testcases shrink materially,
- and claims remain honest.

### M8. Trust / PKI breadth
Goal:
- broader trust and certificate-path realism.

Exit condition:
- narrow carriers no longer define the only honest real-world support story.

### M9. Professionalization
Goal:
- stronger coverage,
- cleaner trace graph,
- cleaner attestation and generated evidence,
- release-quality support statements.

Exit condition:
- the project looks auditable and professional, not just technically promising.

---

## Turn selection algorithm

At the start of each turn:

1. Inspect the current repo state.
2. Identify the **highest-priority incomplete milestone**.
3. Decide whether the repo baseline is clean enough to advance that milestone honestly.
4. If yes, choose the **single best bounded slice** within that milestone.
5. If not, do the smallest stabilization pass needed to restore an honest green baseline.
6. If the milestone is too large for one truthful turn, land the smallest real prerequisite inside it.
7. Only move down the priority ladder when the higher priority item is blocked, complete, or waiting on manual review.

---

## What not to do

- Do not dig into diagnostics/qlog when a higher-priority protocol family is incomplete.
- Do not expand the public API just because internal seams exist.
- Do not claim broad interop from narrow harness success.
- Do not start 0-RTT and anti-replay at the same time if the repo has not earned that combined claim.
- Do not let coverage cleanup replace real protocol progress.
- Do not keep adding prerequisite state if the repo is ready for the next actual behavior slice.

---

## Expected outputs each turn

Each turn should aim to produce one of these:
- a bounded runtime slice,
- a bounded proof/test strengthening slice,
- a bounded trace/design reconciliation slice,
- or a bounded stabilization pass that restores a green baseline.

Each turn should also leave behind:
- an honest summary of what landed,
- exact boundaries and explicit out-of-scope notes,
- the most relevant checks and counts,
- and a local commit if useful changes were made.

---

## Completion criteria for this mission

This mission is complete only when the repo has all of the following:
- a broad enough managed QUIC implementation to be honestly supportable,
- strong black-box interop confidence across a wide slice of the interop project,
- no major protocol-family holes such as 0-RTT, anti-replay, or positive key update still missing,
- and professional-quality evidence, trace hygiene, and release readiness.

Until then, keep choosing the next highest-value bounded slice according to this mission.
