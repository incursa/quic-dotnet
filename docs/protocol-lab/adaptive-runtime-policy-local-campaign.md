---
title: "Adaptive Runtime Permanent Local Campaign"
---

# Adaptive Runtime Permanent Local Campaign

Status: implemented permanent local campaign contract; evidence review in
progress; active policy blocked

This plan defines permanent local evidence required before any adaptive policy
is taken to ProtocolLab. Local results are diagnostic and non-publishable. A
passing local campaign does not authorize package upload, registration, lab
execution, deployment, or publication.

The machine-readable cell contract is
[`../../schemas/adaptive-runtime-policy-local-result-v1.schema.json`](../../schemas/adaptive-runtime-policy-local-result-v1.schema.json).

## Campaign Principles

- Use forced policy values to create real counterfactuals.
- Keep `legacy_current`, `conservative`, and each candidate distinct.
- Freeze and hash every executable binary before the first measured cell.
- Alternate treatment order deterministically; default to A/B/B/A and rotate
  which implementation is A between repetitions when the runner supports it.
- Record an explicit A/B treatment map from each label to the policy and frozen
  benchmark/runtime binary roles; labels alone are insufficient provenance.
- Validate that each sample's treatment and `sequenceIndex` match the declared
  sequence; the schema fixes the standard `ABBA` and `BAAB` orders, while the
  campaign validator owns sample-to-sequence cross-field validation.
- Validate exact payload length and content in every cell.
- Use the same workload definition, runtime, harness, warmup, duration, and
  host controls for compared policies.
- Record target and generator pressure separately.
- Preserve failed, noisy, contradicted, and rejected cells with their original
  classification.
- Never convert a host-regime change into a policy claim by pooling unmatched
  runs.

## Policy Controls

Every eligible axis must expose a test-only forced value. For the first
receive-credit migration, the required values are:

| Value | Meaning |
| --- | --- |
| `legacy_current` | Apply the exact selector and sticky fallback at commit `1b2611e1` |
| `immediate` | Force conservative immediate publication, except correctness paths still publish as required |
| `read_dominant_batch` | Force the frozen half-window mechanism while retaining small-window, saturation, terminal, and ownership guards; campaign metadata records whether sticky-write eligibility was bypassed |
| `shadow` | Apply `legacy_current` and record the controller proposal |

Forced modes bypass selection only. They cannot bypass flow-control progress,
numeric limits, cancellation, disposal, FIN/reset, recovery, congestion,
ownership, or buffer bounds.

The `application_send_turn_planning` raw host accepts independently selected
`legacy_current`, `conservative`, `observe_only`, and `shadow` values.
Forced construction provenance and observe-only/shadow turn records use
separate versioned output streams. The host rejects simultaneous receive-credit
and send-turn selection and explicitly configures adjacent receive-credit
behavior as `legacy_current`. For a send-turn `-ShadowOnly` cell, the permanent
local runner now converts and validates the raw turn records, adds the epoch
rows and export manifest to the checksum inventory, and verifies their result,
sample, and raw-source joins. This implements the evidence path; it does not
classify an unexecuted campaign or authorize active behavior.

## Permanent Workload Matrix

The minimum local campaign crosses the dimensions below. Cells may be split
into bounded phases, but omissions must be explicit in the campaign manifest.

| Dimension | Required values |
| --- | --- |
| Payload | 1 KiB, 64 KiB, 1 MiB |
| Accounting | fixed total bytes and fixed bytes per stream |
| Traffic | upload, download, duplex, request/response, sustained streaming |
| Connections | one and multiple stable connections |
| Stream pressure | c1, c4, c8, c16, c24, c32, c64, plus higher stress only where generator health is proven |
| Arrival | sparse, bursty, sustained, deterministic stream churn |
| Flow control | default window, bounded small window, slow consumer, peer-blocked recovery |
| Network | clean; controlled delay and loss only after the clean matrix is stable |
| Resource | normal host; bounded CPU availability and target/generator pressure where repeatable |
| Peer control | Incursa baseline first; relevant peers only after package and workload parity are proven |

Workload identity is retained for offline analysis but is never a production
controller input.

## Execution Phases

### Phase 0: contract and binary gate

- Validate the campaign manifest and result schema.
- Record repository identities and dirty state.
- Build once, freeze binaries, and record SHA-256 values.
- Refuse a comparison when a binary changes after the campaign begins.
- Capture runtime, OS, CPU, memory, timer, topology, and tool versions.
- Record requested and effective payload, connection, stream, and concurrency
  values independently; the equality flag is a summary, not a substitute.

### Phase 1: cost and neutrality

- Benchmark observation update, snapshot, decision, and policy-read cost.
- Compare the same binary with observation disabled and enabled.
- Require no managed allocation per steady-state observation or decision.
- Confirm disabled observation does not retain timestamps or epoch objects.

### Phase 2: forced counterfactuals

- Run every eligible forced policy value through A/B/B/A matched cells.
- Start with c1, c4, c16, c24, and c32 upload/download/duplex.
- Expand only after correctness and host-health checks pass.
- Retain per-run JSON, stdout, stderr, manifest, hashes, and summaries.

### Phase 3: shadow replay

- Apply `legacy_current` and record controller recommendations.
- Join each shadow epoch only to forced-policy evidence from the same campaign
  cohort and compatible pre-decision regime.
- Measure recommendation stability, transition counts, out-of-domain rate, and
  constrained regret.

### Phase 4: one-axis local activation

This phase remains blocked until the planning bundle and a canonical CRT slice
are approved. When authorized, activate only one axis behind an internal
override. Repeat sparse, target, neighboring, retained-negative, and stress
screens. Do not combine receive-credit and oversized-write controller changes
in one candidate.

### Phase 5: regression gate

Run focused deterministic state, flow-control, cancellation, disposal,
recovery, fairness, and ownership tests, then the complete Release suite. An
isolated rerun may classify a known suite-load sensitivity, but cannot erase a
new deterministic failure.

### Phase 6: ProtocolLab eligibility decision

Only a reviewed local pass may produce a ProtocolLab proposal. The proposal
must name the exact package, scenario, run profile, hosts, hashes, local result
IDs, remaining caveats, and why lab isolation is needed. It is still subject
to operator authorization.

## Result Classification

Every cell has one classification:

- `accepted_local`: all correctness and environment gates passed and the
  result may support the next review step;
- `neutral_local`: correct and stable, with no material policy difference;
- `negative_retained`: correct enough to measure but failed a performance,
  fairness, allocation, memory, or mechanism gate;
- `invalid_environment`: host or generator evidence makes comparison unsafe;
- `invalid_contract`: requested/effective shape, binary, schema, or payload
  identity did not match;
- `failed_correctness`: any payload, protocol, timeout, cancellation,
  disposal, ownership, or terminal invariant failed; or
- `stress_only`: useful diagnosis outside the supported acceptance envelope.

Classification is append-only. A later rerun creates a new result; it does not
rewrite the earlier classification.

## Required Artifacts

Each campaign retains:

- campaign manifest and exact command lines;
- one schema-valid result document per measured cell;
- repository and binary hash inventory;
- requested and effective workload shape;
- raw sample JSON and aggregate summary;
- exact-payload validation and failure details;
- host, target, and generator pressure evidence;
- policy transitions and bounded reason counts for shadow/active runs;
- reviewed missing, stale, out-of-domain, and contradictory-epoch budgets used
  by acceptance and rollback; and
- stdout, stderr, and diagnostic artifacts; and
- a checksum inventory covering every artifact referenced by the result.

The permanent root should be under `.artifacts/adaptive-runtime/<campaignId>`
or another reviewed repo-owned artifact root. Temporary roots may mirror the
layout but cannot be the only retained evidence after a result is accepted.

## Negative-Evidence Rule

The universal receive-credit, half-window duplex-reactivating,
quarter-window duplex-reactivating, non-sticky, and lock-based variants remain
retained negatives. Any future campaign that touches the same axis must link
their evidence and rerun the relevant duplex and low-cardinality screens. A
new threshold alone is not a materially different mechanism.
