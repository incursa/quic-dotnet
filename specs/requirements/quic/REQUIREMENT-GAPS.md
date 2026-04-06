---
workbench:
  type: specification
  workItems: []
  codeRefs: []
  pathHistory: []
  path: /specs/requirements/quic/REQUIREMENT-GAPS.md
---

# QUIC Requirement Gaps

This ledger tracks open questions, ambiguities, and follow-up decisions for QUIC requirement work.

## Open Gaps

- `9002-06-key-discard-lifecycle` is partially reusable at the helper layer, but the RFC 9002 S6P4 0-RTT rejection and secret-discard timing clauses remain blocked until the repo has TLS handshake orchestration and an explicit key-lifecycle surface. The existing recovery helpers can model Initial/Handshake packet accounting after keys are discarded, but they do not expose 0-RTT rejection state or prove when Handshake and 1-RTT keys are available to both endpoints.
- `9000-19-retransmission-and-frame-reliability` is split across send-path, recovery, stream-lifecycle, flow-control, path-validation, connection-ID, and congestion-control behaviors that are not present in the current helper-only transport slice. The implemented subset is limited to ACK freshness and PATH_CHALLENGE payload uniqueness; the remaining S13P3 requirements stay blocked until a sender/recovery architecture exists.
- `9000-02-stream-state` is partially reusable at the helper layer, and the repository now has connection-scoped stream accounting for stream opening, ordered receive buffering, per-stream byte tracking, and final-size bookkeeping. Application-facing stream APIs plus full STOP_SENDING/RESET orchestration remain blocked until the broader transport stack exists.
- `9000-03-flow-control` is partially reusable at the helper layer, and the repository now has connection-scoped flow-control accounting plus monotonic MAX_DATA, MAX_STREAM_DATA, and MAX_STREAMS application. End-to-end sender/recovery orchestration and the remaining transport enforcement needed to fully close S4/S4P1/S4P2/S4P4/S4P5/S4P6 remain blocked until the transport stack grows beyond the helper layer.
- `9000-11-migration-core` is mostly blocked by the absence of connection-migration orchestration, path-selection, packet-sending, and ECN/timer surfaces. The helper layer can limit sends on an unvalidated peer address, but the remaining S9/S9P1/S9P2/S9P3 requirements need a connection-state machine before they can be closed cleanly.
- `9000-13-idle-and-close` is partially reusable at the helper layer, but the silent-close, immediate-close, and draining-state requirements remain blocked until the repo has a connection-state machine and `CONNECTION_CLOSE` wire support. Idle-timeout floor and restart bookkeeping can be modeled independently, but the close/drain lifecycle cannot be completed in the current slice.
- `9000-14-stateless-reset` is partially reusable at the helper layer, but the receive-side draining, token-retirement invalidation, token memory scoping by remote address, and version-aware reset acceptance rules remain blocked until the repo has a connection-state machine and a receive/send policy surface. The stateless-reset packet layout, token generation, and trailing-token comparison helpers can be exercised independently, but the endpoint lifecycle requirements still need the missing connection orchestration.
- `9001-02-security-and-registry` is partially reusable at the helper layer, but the key-update and TLS handshake security clauses remain blocked until the repo has a handshake-confirmation/key-update surface. The short-header Key Phase parser and transport-parameter codec can be exercised independently, and the RFC 9001 S10 registry metadata is now surfaced in helper constants, but the remaining stateful S6/S7/S8/S9 requirements still need the missing TLS orchestration.

## How To Use

- Add a gap here before implementation whenever RFC text leaves more than one plausible interpretation.
- Keep the note short and actionable.
- Reference the owning `SPEC-...` file and the follow-up artifact if one exists.
