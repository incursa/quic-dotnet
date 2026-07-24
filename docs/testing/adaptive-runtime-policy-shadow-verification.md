---
title: "Adaptive Runtime Shadow-Mode Verification"
---

# Adaptive Runtime Shadow-Mode Verification

Status: receive-credit shadow foundation implemented and verified;
application-send turn runtime foundation implemented and focused-test
verified; permanent campaign verification pending; active policy blocked

Shadow mode computes and records a proposed controller snapshot while the
existing runtime behavior remains authoritative. It is the only permitted
first controller mode after the planning bundle is reviewed and a canonical
CRT slice is approved.

## Proof Questions

Shadow verification must answer:

1. Does disabled observation preserve the current binary's behavior and cost?
2. Given identical ordered observations, is controller replay deterministic?
3. Does the first receive-credit shadow rule exactly reproduce the frozen
   legacy selector, including its connection-lifetime sticky fallback?
4. Are recommendations stable, explainable, and conservative when evidence is
   missing, stale, contradictory, or outside the reviewed domain?
5. Would recommendations have selected an acceptable forced policy in matched
   counterfactual campaigns?
6. Does application-send turn shadow capture and recommend at exactly one
   actor-turn boundary while leaving the null-planner baseline authoritative?

## Verification Modes

Use one frozen runtime binary whenever possible:

| Mode | Observation | Applied behavior | Purpose |
| --- | --- | --- | --- |
| `disabled` | Off | `legacy_current` | Neutrality control |
| `observe_only` | On | `legacy_current` | Instrumentation cost and schema proof |
| `shadow` | On plus controller replay | `legacy_current` | Recommendation and transition proof |
| `forced_immediate` | Required capture | Conservative immediate credit | Counterfactual control |
| `forced_read_dominant_batch` | Required capture | Frozen batching mechanism with declared eligibility handling | Counterfactual candidate |

Different binaries may be used only when a same-binary control is impossible;
that limitation must be explicit and hashes must be retained.

### Application-Send Turn Extension

The implemented send-turn runtime slice uses the same `disabled`,
`observe_only`, and `shadow` meanings. Its forced controls are
`forced_legacy_current` and `forced_conservative`. Both currently preserve the
same legal planner behavior, so they prove force identity, provenance, guards,
replay, and rollback only; they are not a policy winner or performance
counterfactual.

Send-turn shadow records an axis-specific observation, recommendation,
applied `legacy_current` identity, bounded reason, and version set without
creating a scheduler consumer. Missing, stale, saturated, contradictory,
recovery-unstable, resource-constrained, terminal, and out-of-domain inputs
recommend `conservative`. The snapshot and recommendation expire after one
actor turn, while already selected logical writes retain their independent
operation latches. The runtime swallows diagnostic sink failures, rejects
simultaneous shadow ownership and non-legacy adjacent-axis forcing, and leaves
the null-planner path authoritative. Versioned raw-host records,
permanent-runner schema-valid epoch/result joins, and the same-binary
disabled-versus-observe-only ABBA runner path are implemented. Executed local
shadow evidence exists; executed neutrality evidence remains required before
this section is verified end to end. Recovery probes do not create
application-send turn records.

## Deterministic Tests

Focused tests must cover:

- entry, insufficient evidence, promotion, minimum dwell, relief, demotion,
  fallback, recovery, quiescence, and terminal transitions;
- duplicate, delayed, missing, stale, saturated, and out-of-order epochs;
- reason-code precedence when multiple guards fire;
- sticky `has_issued_application_data` behavior before, during, and after a
  candidate observation;
- low receive window, credit exhaustion, limit saturation, terminal read,
  FIN, reset, cancellation, disposal, shutdown, and recovery bypasses;
- operation latching across policy snapshot changes;
- exact replay equality for state, snapshot, axis values, and reasons;
- rule-version mismatch and observation-contract mismatch fallback; and
- no per-observation managed allocation after warmup.

Property/fuzz coverage should generate bounded observation sequences and prove
that the controller never emits an undefined policy, never leaves terminal,
never clears a sticky fact, never promotes on missing/stale data, and always
converges to conservative behavior after a guard.

## Runtime Neutrality Tests

- The scheduler, flow-credit, packet, recovery, cancellation, disposal, and
  ownership outputs must match with shadow off and on.
- Shadow output must have no consumer in the scheduling path.
- Disabled instruments must leave enqueue timestamps and epoch storage absent.
- Existing metrics retain bounded tags; shadow capture cannot add connection
  or stream identity to the meter surface.
- The decision function is benchmarked independently and remains materially
  cheaper than a normal actor turn.

## Local Campaign Screens

Run the permanent campaign's exact-payload matrix in this order:

1. c1/c4 upload, download, and duplex neutrality;
2. c16/c24 target receive-heavy rows;
3. c16/c24 duplex sticky-fallback rows;
4. c32 neighboring and saturated rows;
5. small receive-window and slow-consumer flow-control rows;
6. c64 and higher only as stress diagnostics when generator health is proven;
7. cancellation, disposal, reset, FIN, shutdown, loss, and recovery screens.

Retained universal, half-window, quarter-window, non-sticky, and lock-based
negatives must remain linked and their relevant screens must be rerun.

## Shadow Scoring

Report at least:

- epoch count and active duration by state;
- recommendation and transition count by bounded reason;
- percent missing, stale, contradictory, and out-of-domain;
- promotions and demotions per active minute;
- time from regime change to stable recommendation;
- exact agreement with the legacy selector for the semantic-neutral migration;
- constrained regret against compatible forced-policy cohorts;
- correctness, fairness, latency, allocation, retained-memory, loss, and queue
  outcomes by recommendation; and
- disagreement clusters with raw row IDs and provenance.

Throughput alone cannot define a correct recommendation. Any policy that fails
correctness, memory, fairness, or accepted latency constraints is ineligible
for the counterfactual winner set.

## Exit Gate

Shadow mode is ready for an active-policy review only when:

- the planning bundle and canonical CRT artifacts are approved;
- deterministic, fuzz/property, focused, and full-suite tests pass under the
  repo's normal evidence rules;
- disabled vs observe-only same-binary controls are neutral within the
  measurement guardrails;
- the receive-credit migration has 100 percent decision agreement with the
  frozen legacy selector in every in-domain epoch and conservative handling of
  every missing/stale/out-of-domain epoch;
- there are no unexplained oscillation or disagreement clusters;
- forced-policy counterfactuals cover sparse, target, neighboring, retained
  negative, and stress regimes;
- held-out workload and host analysis supports the deterministic rule; and
- rollback to `legacy_current` is proven before activation.

Clearing this gate permits a review, not production activation.
