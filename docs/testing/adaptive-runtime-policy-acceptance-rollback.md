---
title: "Adaptive Runtime Acceptance And Rollback Criteria"
---

# Adaptive Runtime Acceptance And Rollback Criteria

Hardening addendum: readiness labels are not reviewed interaction actuation
proof. Family v2 requires explicit matching axis, value, version, evidence,
and passed review outcome. No canonical proof records were created here;
measurement and active behavior remain unauthorized.

Status: proposed criteria; no production activation authorized

These criteria govern the first proposed controller migration: shadowing and,
only after a later approval, applying the receive-credit publication axis. The
current `legacy_current` behavior at commit `1b2611e1` is the deployment
rollback target. The controller's internal conservative value is immediate
credit publication. These are deliberately distinct so rollback preserves
accepted work rather than silently deleting it.

## Preconditions

Before any active implementation review:

- all seven planning artifacts are reviewed together;
- `adaptive-runtime-controller-policy-bundle` is resolved into stable CRT
  requirements and canonical architecture, work-item, and verification homes;
- forced `legacy_current`, `immediate`, and `read_dominant_batch` values exist
  behind internal/test-only controls;
- shadow output has no production consumer and passes the shadow exit gate;
- binaries, result documents, epoch rows, and checksum inventories validate;
- the retained negative variants and evidence are linked; and
- an internal force-legacy override is proven before active behavior is tried.

## First-Axis Scope

The first active candidate may change only receive-credit publication for new
reads at documented safe boundaries. It may not change the oversized-write
quantum, application-send planner, datagram batching, send burst, actor wake,
packet cadence, or backpressure limits in the same candidate.

The only eligible non-conservative value is the frozen sticky read-dominant
mechanism. Broader eligibility, a new cadence, or clearing the sticky-write
fact requires a new planning and requirement slice.

## Second-Axis Measurement Scope

`application_send_turn_planning` is currently measurement-only. Its
`legacy_current` and `conservative` identities both retain the current legal
null-planner scheduler; observe-only and shadow always apply
`legacy_current`. The exact rollback target is the force-legacy/null-planner
path, and forced identities remain subject to priority, ordering, congestion,
pacing, recovery, flow-control, ownership, lifecycle, queue, and buffer
guards.

One same-host disabled-versus-observe-only cell is retained as
`negative_retained` because observe-only p95 exceeded the five-percent matched
guardrail. It does not qualify this axis for active review. The broader
neutrality matrix, complete Release correctness suite, independent-host
counterfactual coverage, honest host and workload holdouts, deterministic
offline replay, fairness outcomes, and campaign rollback proof remain required
before a behavior-distinct rule can be proposed. No behavior-distinct planner
or `active_internal` application is authorized by this measurement scope.

## Acceptance Gates

All gates are conjunctive.

### Correctness and progress

- Zero payload-validation, protocol, timeout, malformed-operation, ownership,
  cancellation, disposal, reset, FIN, shutdown, or recovery regressions in
  accepted cells.
- Required credit publication always bypasses policy under low headroom,
  blocking, saturation, terminal, or recovery conditions.
- Focused deterministic and property/fuzz tests pass.
- The complete Release suite passes, subject only to explicitly retained
  pre-existing load sensitivities with immediate isolated proof and no new
  deterministic signature.

### Determinism and explainability

- Ordered replay is byte-for-byte identical in state, snapshot, and reason.
- Every transition has one bounded reason code and source epoch.
- No benchmark label, payload constant, scenario ID, requested concurrency, or
  peer identity is a production feature.
- Missing, stale, contradictory, saturated, and out-of-domain inputs choose the
  conservative value.

### Stability

- No unexplained promotion/demotion cycle occurs during a stable workload.
- Normal transitions respect reviewed consecutive-epoch and dwell settings.
- A hard fallback occurs within the next actor-safe boundary.
- Repeated transitions do not change in-flight fragmentation, ordering,
  completion, or ownership semantics.

### Performance, latency, fairness, and memory

- c1 and c4 upload/download/duplex throughput, p95, and allocation stay within
  a five-percent matched guardrail unless a stricter existing gate applies.
- The retained c16/c24 duplex screens do not reproduce the 50-122 percent tail
  regressions of the rejected cadences; p95 may not regress more than five
  percent in a stable matched cohort.
- No accepted target or neighboring row regresses throughput more than five
  percent, allocation more than five percent, or peak retained bytes more than
  five percent without an explicit tighter byte bound and review.
- A target improvement is credited only when repeated matched evidence shows
  at least a five-percent material gain in two independent in-domain workload
  families or when it removes a separately defined capacity failure without
  violating other gates.
- c32 is a neighboring gate, while c64 and higher remain stress diagnostics
  unless generator and environment health qualify them for acceptance.

### Shadow and holdout quality

- Semantic-neutral shadow migration has 100 percent agreement with the frozen
  legacy selector for in-domain epochs.
- Forced-policy evidence exists for every recommendation class.
- Workload-family and host holdouts satisfy the same correctness and guardrail
  constraints.
- There is no unexplained high-regret or out-of-domain cluster.

## Activation Sequence

1. `legacy_current` with observation disabled.
2. `legacy_current` with observation enabled.
3. Shadow controller with `legacy_current` applied.
4. Explicitly approved local `active_internal` for one axis.
5. Focused and complete local gates.
6. Operator-reviewed ProtocolLab proposal, if local evidence justifies it.
7. Any broader rollout only through a separate approval and release plan.

Skipping a stage invalidates later evidence.

## Rollback Triggers

Immediately force `legacy_current` and stop further promotion when any of the
following occurs:

- any new correctness, timeout, protocol, cancellation, disposal, terminal,
  recovery, ordering, or ownership failure;
- duplex or low-cardinality p95 regression beyond the five-percent guardrail;
- allocation or retained-buffer growth beyond its accepted bound;
- throughput regression beyond its gate in sparse, target, or neighboring
  regimes;
- oscillation, repeated contradictory recommendations, or reason-code gaps;
- missing, stale, incompatible, contradictory, or out-of-domain observation
  percentages above the explicit budgets stored in the result's
  `policyConfiguration.anomalyBudgets`;
- rule, observation, binary, schema, or checksum version mismatch;
- evidence that forced policy did not match the declared applied policy; or
  host/generator health that prevents an honest decision.

A correctness trigger aborts the candidate even if aggregate throughput
improves.

## Rollback Mechanism

Rollback must be deterministic, connection-safe, and independently tested:

- new connections use `legacy_current` through an internal override;
- existing connections stop new controller promotions at the next actor-safe
  boundary;
- in-flight operations retain their latched ownership and completion policy;
- correctness guards continue to force immediate progress;
- no queue, credit, buffer, timer, recovery, or controller state is discarded;
- controller output may continue in diagnostic shadow only if it cannot affect
  behavior and the incident owner approves capture; and
- the rollback does not delete the candidate, dataset, negative results, or
  transition history.

If the controller itself is suspected, a baseline-only build or internal
disable path must remain available without changing the public API.

## Post-Rollback Classification

Create a new `negative_retained` or `failed_correctness` result with the trigger,
first affected epoch, rule and binary versions, exact commands, hashes,
artifacts, and rollback time. Preserve the last known-good result and the
failed result separately. Do not rewrite an accepted row or reuse the failed
rule version for a later threshold-only retry.

Production implementation remains blocked until these criteria are reviewed
and the trace-first prerequisite is complete.

The first operation-correlated slice adds two rollback prerequisites for batch
formation and buffer coalescing: a forced candidate that is ineligible must
not remain applied, and every materialized combined-owner operation must join
to exactly one terminal release. Inactive, clamped, fallback, invalid, and
negative rows remain retained. These correctness proofs do not clear a
performance-acceptance, interaction-execution, `active_internal`, or
production-activation gate.
