---
title: "Adaptive Runtime Stage 3 Packet and Receive Foundation"
---

# Adaptive Runtime Stage 3 Packet and Receive Foundation

Status: `packet_flush_cadence` implementation-ready; measurement and active
behavior frozen; `receive_delivery_quantum` next

This document is the trace home for the ordinary Stage 3 axes in
[`adaptive-runtime-policy-axis-roadmap.md`](adaptive-runtime-policy-axis-roadmap.md).
It does not replace the roadmap or authorize performance measurement,
`active_internal`, or production behavior.

## Packet Flush Cadence

Axis ID: `packet_flush_cadence`

Closed values:

- `legacy_current` retains the existing optional one-millisecond coalescing
  delay for an eligible application write smaller than 32 bytes.
- `prompt` removes only that optional delay and continues through the existing
  direct-send packet-protection and accounting path.

The decision occurs after stream reservation and payload construction and
before the optional delay or packet protection. It is latched for one
logical-write packet opportunity. Disabled and unforced operation preserves
the original branch exactly. Observe-only records the legacy decision.
Shadow recommends `prompt` while applying `legacy_current`. Internal forcing
supports each closed value, and force-legacy rollback restores the optional
delay.

Forced mode bypasses selection only. Retransmission priority, address
validation and amplification, lifecycle, congestion, pacing, flow control,
packet size and protection, recovery, cancellation, terminal state, and
ownership remain authoritative. Missing, stale, saturated, contradictory,
invalid, out-of-domain, retransmission, validation, or lifecycle state falls
back to `legacy_current`.

One packet-opportunity record is sample-scoped. Its deterministic raw join key
is the source-log identity, connection key, and operation sequence. The
configured snapshot and bounded inclusive operation range remain in every
unified connection epoch. Sample counts and epoch counts are distinct.

Trace chain:

- `REQ-QUIC-CRT-0192`
- `ARC-QUIC-CRT-0071`
- `WI-QUIC-CRT-0072`
- `VER-QUIC-CRT-0073`

## Receive Delivery Quantum

Axis ID: `receive_delivery_quantum`

This axis remains an inventory item. Its implementation must preserve
`receive_credit_publication=legacy_current` and identify one bounded delivery
or wake unit that does not change receive-buffer ownership, FIN/reset/close
ordering, cancellation/disposal, flow-control progress, or terminal drain.
No policy value, force seam, or active behavior is claimed yet.

## Frozen State

- Every adjacent applied axis remains `legacy_current`.
- No campaign axis varies during implementation.
- No performance campaign, BenchmarkDotNet run, transform, dataset, or ML
  analysis is authorized.
- Scenario, workload, payload constants, requested concurrency, peer, URL,
  host, and application identity are provenance only and never controller
  inputs.
- No CI change, push, `active_internal`, or production activation is
  authorized.
