---
title: "Adaptive Runtime Policy Axis Implementation Matrix"
---

# Adaptive Runtime Policy Axis Implementation Matrix

Status: implementation-breadth checkpoint; measurement and active behavior
remain unauthorized

This matrix is the checkpoint-oriented companion to
[`adaptive-runtime-policy-axis-roadmap.md`](adaptive-runtime-policy-axis-roadmap.md).
The roadmap remains the approved direction and is not replaced by this file.
The matrix records implementation readiness without treating performance
acceptance, threshold tuning, campaign execution, or offline analysis as a
prerequisite for a correct internal seam.

`yes` means the capability is present and has focused deterministic proof.
`foundation` means bounded evidence exists but the axis-level capability is not
yet present. `no` means the capability has not been implemented. Every ordinary
axis remains inactive unless a later explicit review authorizes
`active_internal`.

| Axis ID | Stage | Legacy implementation | Conservative implementation | Observable | Shadowable | Forceable | Unified-row representation | Safety guards | Rollback test | Focused correctness status | Exact blocker | Implementation commit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `receive_credit_publication` | 0 foundation | retained read-dominant selector | `immediate` | yes | yes | yes | yes | flow-control progress, pending-credit flush, sticky application-write fallback, lifecycle | yes | accepted foundation | none for the retained internal seam; active selection remains unauthorized | `1b2611e1`, `55cea560`, `6e408789` |
| `application_send_turn_planning` | 1 | retained injected planner | bounded conservative planner | yes | yes | yes | yes | priority, same-stream order, FIN, ownership, recovery, congestion, pacing, flow control, packet/queue/buffer, lifecycle | yes | implementation-ready | no implementation blocker; measurement remains frozen | `c5f9dae0`, `69e08f34`, `2fbde7bb`, `a8858010` |
| `application_send_batch_formation` | 1 | existing eligible-prefix packing | `single_eligible` | yes | yes | yes | yes | legal prefix and payload cap, priority, same-stream order, FIN, ownership, congestion, pacing, anti-amplification, flow control, packet/queue/buffer, lifecycle | yes | implementation-ready | no implementation blocker; measurement remains frozen | `1713b6a8` |
| `queued_send_burst_budget` | 1 | retained pre/post-confirmation static budget | `single_datagram` | yes | yes | yes | yes | congestion, pacing, anti-amplification, recovery, retransmission, handshake, packet, endpoint, flow control, queue/buffer, lifecycle rechecked per datagram | yes | implementation-ready | no implementation blocker; measurement remains frozen | `fb520dd7` |
| `oversized_write_admission_quantum` | 1 | retained dispatcher plus bounded observer selector | `single_fragment`; distinct `bounded_multi_fragment` candidate | yes | yes | yes | yes | dispatcher availability, logical-write ownership, FIN, retry, recovery, congestion, pacing, anti-amplification, flow control, packet/queue/buffer, lifecycle, exactly-once completion | yes | implementation-ready | no implementation blocker; measurement remains frozen | `7d41e382` |
| `actor_work_quantum` | 2 | current connection-work-item dispatch to completion | none yet | foundation | no | no | actor-service epoch and continuation-assessment foundation | actor transition/effect ownership, exactly resumable work, progress, repost correctness, cross-connection service | no | continuation assessment focused proof clean | no reviewed cooperative-yield boundary owns an exactly resumable unit; a distinct forced value would currently be behaviorally fake or could split transition/effect ownership | `19f69274`, `36c5bad6`, `11bb8496`, `90aaf93b`, `4da502d9` |
| `ready_stream_fairness` | 2 | current planner/queue priority plus stable-sequence order and same-stream serialization | none yet | partial | no | no | no axis record yet; bounded actor and send-path inputs are available | no same-stream reordering, priority authority, FIN/reset/cancellation, flow-control and recovery progress, bounded runnable inspection | no | inventory blocked safely | the current planner selects a priority/sequence prefix; a one-write treatment would silently vary `application_send_batch_formation`, while rotation needs a reviewed bounded runnable set and starvation/fairness outcome rather than an unbounded stream scan | none |
| `buffer_copy_coalescing` | 2 | exact existing combined-send prefix construction | `memory_conservative`, lower-only two-source-segment cap | yes | yes | yes | yes; configured snapshot plus legal/applied operation and fixed epoch fields | Stage 1 legal prefix, priority/order, FIN/reset/cancellation, flow control, stream capacity, packet size, congestion, pacing, anti-amplification, recovery, packet protection, owner transfer/return, terminal cleanup | yes | 18 axis tests, 86 buffer/unified tests, and 164 adjacent Stage 1 tests clean | no implementation blocker; measurement remains frozen | `df8ee570` |
| `adaptive_backpressure` | 2 | immediate admission under existing authoritative hard limits | `early_delay`, at most one additional dispatcher turn when an earlier application-send admission remains queued | yes | yes | yes | yes; configured snapshot plus sample-scoped admission records and fixed epoch summary | hard queue/buffer/stream/flow-control limits, lifecycle, progress, continuation availability, cancellation/disposal/terminal removal, ownership and exactly-once completion | yes | 20 axis tests plus unified raw schema and exact sample-to-epoch join tests clean | no implementation blocker; measurement remains frozen | `25fa33cc` |
| `packet_flush_cadence` | 3 | retained optional 1 ms coalescing delay for eligible application writes smaller than 32 bytes | `prompt`, which removes only that optional delay | yes | yes | yes | yes; configured snapshot plus sample-scoped packet-opportunity records and fixed epoch summary | retransmission priority, address validation and anti-amplification, lifecycle, congestion, pacing, flow control, packet size/protection, recovery, ownership, cancellation and terminal paths | yes | 19 axis tests plus unified raw schema, exact sample-to-epoch join, package, FIN, cancellation, and application-send delay tests clean | no implementation blocker; measurement remains frozen | `c676795b` |
| `receive_delivery_quantum` | 3 | existing loop copies every contiguous receive source segment that fits one application read | `single_segment`, which returns a legal short read after at most one existing contiguous source segment | yes | yes | yes | yes; configured snapshot plus sample-scoped productive-read records and fixed epoch summary | `receive_credit_publication=legacy_current`, ordering, buffer ownership/release, FIN/reset/close, cancellation/disposal, flow-control progress, congestion, pacing, recovery, packet limits, terminal behavior | yes | 17 axis cases plus unified raw schema, exact sample-to-epoch join, aggregate recomputation, listener propagation, and package assertions clean | no implementation blocker; measurement remains frozen | `971c3c46` |
| `connection_shard_placement` | 4 | sequential connection-handle modulo shard count | `bounded_power_of_two_choices`, comparing the legacy shard with one deterministic alternate and choosing the lower active-connection count with a legacy tie break | yes | yes | yes | yes; one immutable connection-start decision repeated in every unified epoch | valid shard bounds, unique runtime/handle ownership, exact registration rollback and unregister accounting, immutable routing, lifecycle, shutdown, endpoint/timer/packet routing, congestion, pacing, recovery, flow control, packet, queue, and buffer authority | yes | 19 axis cases plus placement/host/listener coverage, unified schema composition, stable-latch validation, and raw-host build clean | no implementation blocker; measurement remains frozen | `f6739bfa` |
| `application_datagram_batch_transport` | 4 | retained capability-gated server segmentation and one-way client pressure promotion | `ordinary_datagrams`; distinct forced `segmented_batch` remains capability-gated | yes | yes | yes | yes; configured identity, capability epoch, last decision, and bounded socket/datagram/segment/byte/failure outcomes in every unified epoch | exact platform/address-family/socket/custom-sender capability, endpoint and source-address routing, ECN, packet-size/segmentation, partial-send, ownership, cancellation, disposal, shutdown, recovery, congestion, pacing, flow-control, queue, and buffer authority | yes | 25 axis cases; 144-case focused adaptive, unified, package, socket, terminal, cancellation, and ownership band clean; unified v12/raw v12/manifest v13 fixture and raw-host build clean | no implementation blocker; measurement remains frozen | `c9f6ec39` |
| `congestion_pacing_profile` | 5 separate safety architecture | current congestion and pacing behavior | not defined | no | no | no | no separate axis contract | congestion/recovery/network safety, pacing, loss response, immutable connection-start selection | no | preparation not started | requires separate requirements, architecture, verification, network-safety review, force contract, and campaign plan | none |
| `ack_behavior_profile` | 5 separate safety architecture | current ACK behavior | not defined | no | no | no | no separate axis contract | peer/RFC bounds, loss response, packet-number-space state, mandatory ACK progress | no | preparation not started | requires separate requirements, architecture, verification, network-safety review, force contract, and campaign plan | none |
| `crypto_execution_profile` | 5 separate safety architecture | current inline execution paths | not defined | no | no | no | no separate axis contract | packet-number uniqueness, packet protection, key phase, authenticated ownership, queue latency and fallback | no | preparation not started | requires platform capability research plus separate security architecture, verification, force contract, and campaign plan | none |
| `http3_qpack_profile` | 5 separate component architecture | current HTTP/3 priority and QPACK behavior | not defined | no | no | no | no separate axis contract | QPACK blocking bounds, stream ownership/progress, cancellation, request/header-block boundary, protocol compliance | no | preparation not started | requires separate HTTP/3 requirements, architecture, verification, security/protocol review, force contract, and campaign plan | none |
| `runtime_pressure_advice` | observation-only advisor | absent | absence must remain valid | no | not applicable | not applicable | optional coarse provenance only | bounded immutable sample, stale/missing fallback, never a controller or policy owner | not applicable | not started | advisor contract and platform providers are not implemented; it is not an axis and does not block independent seams that do not require it | none |

## Current Progression Decision

The continuation-assessment checkpoint does not make
`actor_work_quantum` forceable, and the ready-stream inventory records the
independent bounded-runnable and real-outcome blocker without inventing a
fairness treatment. `buffer_copy_coalescing` is the first implementation-ready
Stage 2 axis: it makes a lower-only decision after Stage 1 has produced the
legal prefix and cannot widen or reorder that prefix.

`adaptive_backpressure` now has the reviewed wait-only `early_delay` seam:
one additional dispatcher turn at new application admission only when an
earlier application-send admission remains queued. It cannot reject, fail,
raise a hard limit, wait for network progress, or change ownership after
admission. The actor and ready-stream axes retain their exact safety blockers;
neither may be represented by fabricated values or additional unbounded
observation work.

`packet_flush_cadence` now owns only the existing optional small-write delay
after payload construction and before packet protection. `prompt` removes
that optional delay for one logical-write packet opportunity; it cannot flush
otherwise ineligible work or bypass retransmission, validation, recovery,
congestion, pacing, flow-control, packet, lifecycle, or ownership authority.

`receive_delivery_quantum` owns only the number of existing contiguous source
segments that contribute to one productive application read. `single_segment`
cannot change wake scheduling, receive-credit selection, ordering, ownership,
FIN/reset/close, cancellation, or terminal behavior.

`application_datagram_batch_transport` now owns only the contiguous segmented
construction proposal and the capability-gated socket transport choice.
`legacy_current` preserves the capable server path and the client one-way
pressure promotion. `segmented_batch` remains subordinate to the exact socket
capability epoch, while `ordinary_datagrams` is the conservative independent
send-call path. Unsupported capability, invalid observation, and lifecycle
state fall back to ordinary sends even under forcing. Endpoint, socket,
packet, ownership, partial-send, recovery, congestion, pacing, flow-control,
queue, and buffer authority remain unchanged. Stage 4 ordinary axis
implementation is complete; the next work is the separate Stage 5
protocol-sensitive preparation package.

## Frozen Operational State

- No campaign axis varies during implementation checkpoints.
- `receive_credit_publication` and all implemented adjacent axes apply
  `legacy_current`.
- Existing unified observations remain present.
- Performance measurement, large dataset work, transforms, and offline
  analysis remain frozen.
- `active_internal` and production activation remain unauthorized.
- CI and push are out of scope.
