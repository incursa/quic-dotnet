# QUIC Triage

As of 2026-04-05, the repository already has live QUIC helper-layer code, requirement-tagged tests, and generated trace artifacts. It is not scaffold-only. The closed RFC 8999 slice, packet/header and stream substrate, transport-parameter helpers, and recovery/congestion helpers are all present, while the remaining transport slices still need trace closure and end-to-end orchestration.

## Sources

- [Requirements workflow](requirements-workflow.md)
- [Requirement gaps](../specs/requirements/quic/REQUIREMENT-GAPS.md)
- [Generated coverage triage](../specs/generated/quic/quic-requirement-coverage-triage.md)
- [Existing work inventory](../specs/generated/quic/quic-existing-work-inventory.md) - the current planning snapshot. It was rebaselined from the live source/test surface because the repository does not yet ship a dedicated inventory generator.
- [Implementation chunk manifest](../specs/generated/quic/implementation-chunk-manifest.md)
- [QUIC verification](../specs/verification/quic/README.md)
- [Benchmarks](../benchmarks/README.md)

## Current Position

| Area | State | Practical Meaning |
| --- | --- | --- |
| RFC 8999 | Closed out | The long-header invariant slice is implemented, tested, fuzzed, benchmarked, and already has closeout evidence. |
| RFC 9000 | Mixed | Packet-header, varint, version-negotiation, short-header, stream parsing, transport-parameter, address-validation, path-validation, idle-timeout, stateless-reset, ACK, and recovery helpers exist, but stream state, flow control, connection lifecycle, migration, and most control-plane slices are still open. |
| RFC 9001 | Helper-layer partial | AEAD usage-limit helpers and tests exist, but packet-protection, key-derivation, and key-update remain end-to-end work. |
| RFC 9002 | Helper-layer partial | RTT, recovery-timing, congestion-control, ACK/recovery bookkeeping, and related helper surfaces exist, but sender orchestration and PTO integration are still incomplete. |

## Coverage Snapshot

The current generated triage report shows:

| State | Count |
| --- | ---: |
| trace_clean | 116 |
| covered_but_missing_xrefs | 6 |
| covered_but_proof_too_broad | 358 |
| partially_covered | 128 |
| uncovered_blocked | 314 |
| uncovered_unblocked | 814 |

That means the repo has meaningful implementation evidence already, but most of the canonical requirement surface still needs either tighter proof or first-pass implementation.

## What Needs To Happen Next

1. Finish the stream-state and flow-control foundations in RFC 9000.
2. Close the connection-ID, connection-establishment, and packet-classification slices that depend on the packet-header foundation.
3. Work through the RFC 9000 connection lifecycle, migration, idle/close, stateless-reset, error-handling, ACK, loss, datagram, frame, transport-parameter, and registry slices in dependency order.
4. Add the RFC 9001 packet-protection and key-update surface after the packet and stream plumbing is stable.
5. Finish the RFC 9002 sender/recovery integration on top of the existing helper layer.
6. Keep the gap ledger current whenever a slice is ambiguous or blocked by missing transport state.

## Existing Implementation Base

The repo already has live helper and parser code under `src/Incursa.Quic` for:

- packet headers and version negotiation
- varint decoding / encoding
- stream ID and STREAM frame parsing
- frame codec helpers
- transport parameter codec helpers
- address validation and anti-amplification budgeting
- idle timeout tracking
- path validation
- stateless reset helpers
- ACK generation
- recovery timing and PTO helpers
- RTT estimation
- congestion control state
- AEAD usage-limit helpers

Permanent fuzzing and benchmark surfaces already exist for the parser and helper hot paths.

## Doc Debt

- [Generated existing-work inventory](../specs/generated/quic/quic-existing-work-inventory.md) was rebaselined manually because there is no checked-in generator for that snapshot yet, and the companion implementation chunk manifest still needs the same treatment if we want repeatable regeneration.
