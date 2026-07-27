# Adaptive-runtime implemented-factor onboarding

Status: implementation checkpoint

Date: 2026-07-26

Trace:

- requirements: `REQ-QUIC-CRT-0235` through `REQ-QUIC-CRT-0240`
- architecture: `ARC-QUIC-CRT-0113`
- work item: `WI-QUIC-CRT-0114`
- verification: `VER-QUIC-CRT-0115`

## Decision

This checkpoint onboards exactly:

- `oversized_write_admission_quantum`
- `queued_send_burst_budget`

`packet_flush_cadence` is deferred. Its runtime mechanism is implemented and
forceable, but the reviewed prose currently understates its activation
predicate: queued work can make the retained optional delay eligible even when
the payload is at least the 32-byte threshold. Correcting that contract belongs
to its own onboarding checkpoint.

The new axes do not enlarge the existing `send_composition` family merely
because all four may affect top-level performance. The canonical family split
is:

- `send_admission_composition`: oversized-write admission supplies logical
  fragments to application-send batch formation, which supplies selected work
  to buffer-copy coalescing.
- `queued_send_burst_correctness`: queued-send burst owns a later actor-turn
  emission cap and is initially a single-axis correctness family.

No new multi-axis runtime capability is authorized. Candidate proofs remain
external-review pending. Measurement and active behavior remain unauthorized.

## Canonical-state reconciliation

Activation proof, correctness eligibility, experiment result, and rule
promotion are separate facts:

| Fact | Batch/buffer state |
| --- | --- |
| activation proof | reviewed and passed for `single_eligible` and `memory_conservative` |
| correctness eligibility | reviewed single-axis and exact two-axis correctness cells are eligible |
| holdout extension | completed with activation-qualified holdouts |
| rule promotion | `no_stable_rule`; no selector or threshold was emitted |

`no_stable_rule` is a valid completed measurement result. It does not negate
actuation or correctness proof, and it does not authorize active behavior.

## Candidate-axis audit

### `oversized_write_admission_quantum`

- implementation: implemented, forceable, shadowable, rollback-capable
- values: `legacy_current`, `single_fragment`, `bounded_multi_fragment`
- planned-but-unimplemented values: none
- owner: connection actor / logical-write admission
- scope: one oversized logical write
- boundary: after the runtime establishes that the logical write exceeds the
  retained fragment limit and before the first fragment is dispatched
- latch: the logical write through completion, cancellation, disposal, or
  terminal outcome
- authority: select a bounded one- or two-fragment service quantum; it may
  neither change bytes/order/FIN/ownership nor bypass downstream guards
- switching cost: one logical-write latch; no retained controller state
- operation opportunity: logical write larger than the retained maximum stream
  write chunk
- `single_fragment` distinctness: two fragments are legal and the retained
  selector would choose two
- `bounded_multi_fragment` distinctness: two fragments are legal and the
  retained selector would choose one
- primary mechanisms: one fragment per actor service opportunity; bounded two
  fragments per actor service opportunity
- fallback: legal/resource/dispatcher/lifecycle guards may clamp to the
  one-fragment mechanism or terminate the write
- inactivity: a write fitting one fragment
- evidence: decision and logical-write identity, legal/applied quantum,
  committed fragments/bytes, continuation posts, completion outcome
- direct downstream edge: `oversized_write_admission_quantum` supplies work to
  `application_send_batch_formation`
- operation-local constraint: a raw oversized fragment is a single batch write
  and cannot itself be simultaneously batch- or buffer-distinct in that
  decision opportunity
- cell-level consequence: none is currently proved; later fragments,
  continuations, packet plans, or operations can still expose downstream batch
  and buffer behavior in the same configured workload cell
- direct oversized-to-buffer edge: intentionally omitted; the influence is
  transitive through batch formation
- candidate proof: separate immutable chains now bind `single_fragment` to
  the 16-observer legacy-two case and `bounded_multi_fragment` to the
  sparse-observer legacy-one case. Both remain external-review candidates.

### `queued_send_burst_budget`

- implementation: implemented, forceable, shadowable, rollback-capable
- values: `legacy_current`, `single_datagram`
- planned-but-unimplemented values: none
- owner: connection actor / recovery-progress actor turn
- scope: one queued-send actor turn
- boundary: after the authoritative transport send budget is computed
- latch: one actor turn; the legal budget is rechecked for every datagram
- authority: lower-only cap of an already legal datagram budget to one
- switching cost: one actor-turn latch; no retained controller state
- activation: legal maximum datagrams greater than one, one datagram emitted,
  burst-limit outcome, and queued work remaining
- inactivity/equivalence: legal cap at most one or the queue drains after the
  first datagram
- primary mechanisms: retained legal actor-turn budget; one-datagram actor-turn
  cap
- fallback: retransmission, congestion, pacing, path/protection,
  anti-amplification, lifecycle, or invalid-budget guards retain a blocked or
  legacy-safe result
- evidence: decision and actor-turn identity, legal/applied maximum datagrams,
  emitted datagrams, queue before/after, outcome and block reason
- relationship to packet flush: packet flush changes whether work reaches the
  queued-send actor; it is not authority overlap
- relationship to datagram batching: actor-turn packet count changes observed
  batching opportunity, but does not own datagram construction
- relationship to batch formation: queued burst supplies repeated packet-plan
  opportunities; batch selection can change whether a later burst iteration
  exists
- candidate proof: the immutable chain binds the existing live actor-turn
  evidence to exact composite operation identity, catalog materialization,
  retained fallback, shadow neutrality, rollback, and projection. It remains
  external-review pending.

### `packet_flush_cadence` (deferred)

- implementation: implemented, forceable, shadowable, rollback-capable
- values: `legacy_current`, `prompt`
- authority: retain or remove only the existing optional application-send delay
- boundary/latch: one constructed non-oversized application-write packet
  opportunity
- actual distinctness predicate: valid nonterminal input, no retransmission,
  positive payload, validated address, and either queued work or payload below
  the retained delay threshold
- direct relationship: it changes queued state observed by queued burst and
  batch formation
- reason deferred: contract text needs a narrow predicate correction and the
  proof bridge must retain the post-decision timer/send transition
- family candidate: a later queue/cadence family with queued burst, not the
  current batch/buffer family

## Relationship inventory

| Source | Target | Type | Canonical treatment |
| --- | --- | --- | --- |
| oversized admission | batch formation | `supplies_work` | direct edge |
| oversized admission | buffer coalescing | `structural_constraint` | operation-local noncoactivation represented as a constraint, not a duplicate direct graph edge or a cell-level exclusion |
| batch formation | buffer coalescing | `supplies_work` | retained direct edge |
| queued burst | packet flush | `changes_observed_state` | direction is packet flush to queued burst in a future graph because flush choice changes queue arrival |
| queued burst | datagram transport | `changes_observed_state` | documented context; target axis is not onboarded here |
| batch formation | queued burst | `changes_observed_state` | documented context; current distinct pair remains prohibited |

Shared throughput, latency, CPU, copy, or memory outcomes alone do not establish
an experimental relationship.

## Behavior and equivalence

Equivalence is based on the complete primary behavior signature under the
reviewed activation predicate. A shared fallback never collapses two values.

- Oversized legacy has a context-dependent retained selector.
- `single_fragment` is distinct in contexts where legacy selects two.
- `bounded_multi_fragment` is distinct in contexts where legacy selects one
  and two are legal.
- Queued `single_datagram` is distinct only when more than one datagram is
  legally and actually available to the actor turn.
- Inactive and fallback operations remain retained verification evidence.

## Effective-space decision

The v1 cell-space document is retained as historical checkpoint evidence. The
canonical v2 report separates mutually exclusive cell partitions from
overlapping annotations:

- partitions are `correctness_executable`, `capability_pending`,
  `cell_structurally_inactive`, and `rejected`; their counts sum to the
  post-legality cell count;
- annotations such as `measurement_blocked`, `verification_only`,
  `operation_local_noncoactivation`, and `safety_clamped` may overlap the
  partitions and each other;
- `distinct_effective_cell_count_including_baseline` always includes the
  effective baseline cell; and
- `nonlegacy_behavior_distinct_treatment_value_count` counts only nonlegacy
  behavior-distinct axis/value treatments.

`send_admission_composition` has:

- raw configured cells: `3 × 2 × 2 = 12`
- explicit cells after nominal enumeration: 12
- distinct effective correctness cells, including baseline: 5
- nonlegacy behavior-distinct treatment values: 4
- current correctness-executable multi-axis cells involving the new factor: 0
- candidate single-axis actuation cells: 4 configured oversized cells across
  its two independent two-cell plans
- capability-pending cells: 7
- cell-structurally-inactive cells: 0
- operation-local noncoactivation annotations: 6
- multi-axis cells remain retained and capability-pending; operation-local
  noncoactivation does not remove them from a future workload-level
  interaction space

`queued_send_burst_correctness` has:

- raw configured cells: 2
- explicit cells: 2
- distinct effective correctness cells, including baseline: 2
- nonlegacy behavior-distinct treatment values: 1
- candidate single-axis actuation cells: 2

The three new proof documents have `review_status = candidate` and
`review_outcome = null`. They are not present in canonical reviewed-proof
metadata. External review inputs are emitted separately for
`single_fragment`, `bounded_multi_fragment`, and `single_datagram`, each bound
to its exact proof hash, evidence reference, catalog base hash, and independent
review outcome. No all-at-once promotion template is canonical or applied.

Both spaces are no larger than 64. Exhaustive explicit enumeration is stronger,
clearer, and inexpensive. No covering-array generator or placeholder is added.
The compiler continues to consume ordinary explicit `planned_cells`.

## Stopping boundary

This checkpoint does not:

- review or pass the new proof candidates;
- execute a newly expanded multi-axis family;
- authorize performance measurement;
- derive a selector, threshold, ranking, or model;
- activate `active_internal` or production behavior;
- migrate packet flush or another axis;
- modify CI or push.
