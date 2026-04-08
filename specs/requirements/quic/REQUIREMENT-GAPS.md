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
- `9002-06-appendix-b-constants-and-examples` is split into a helper-backed executable subset and a deferred remainder. The helper-backed `SBP1`, `SBP2-0002`, `SBP2-0004`, `SBP2-0005`, `SBP3`, `SBP4`, `SBP5`, `SBP6`, `SBP7`, and `SBP8` clauses can move now, while `REQ-QUIC-RFC9002-SBP2-0001`, `REQ-QUIC-RFC9002-SBP2-0003`, and `REQ-QUIC-RFC9002-SBP9-0001` through `REQ-QUIC-RFC9002-SBP9-0003` remain blocked until the repo has sender/runtime PMTU accounting and connection-owned key-discard cleanup. The retained `REQ-QUIC-RFC9002-SBP9-0003` / `REQ-QUIC-RFC9002-SAP11-0003` overlap stays under manual review.
- `9000-19-retransmission-and-frame-reliability` is split across send-path, recovery, stream-lifecycle, flow-control, path-validation, connection-ID, and congestion-control behaviors that are not present in the current helper-only transport slice. The helper-backed subset now closes `REQ-QUIC-RFC9000-S13P3-0010` and `REQ-QUIC-RFC9000-S13P3-0027`; 25 clauses remain partial and 12 remain blocked until the repo grows sender/recovery orchestration and the other missing transport surfaces.
- `9000-02-stream-state` is partially reusable at the helper layer: 16 clauses across S3/S3P1/S3P2 are now proven by helper-state tests, while 10 clauses remain partially implemented and 40 remain blocked until the repo grows the application-facing stream abstraction, sender/recovery orchestration, and STOP_SENDING/RESET coordination.
- `9000-03-flow-control` is substantially reusable at the helper layer: 43 clauses across S4/S4P1/S4P2/S4P4/S4P5/S4P6 are now proven by helper-state, codec, and transport-parameter tests. The remaining explicit blockers are `REQ-QUIC-RFC9000-S4P5-0001` (partial until sender/recovery reliability exists), `REQ-QUIC-RFC9000-S4P1-0015`, `REQ-QUIC-RFC9000-S4P2-0001` through `REQ-QUIC-RFC9000-S4P2-0004`, and `REQ-QUIC-RFC9000-S4P6-0013`.
- `9000-11-migration-core` is mostly blocked by the absence of connection-migration orchestration, path-selection, packet-sending, and ECN/timer surfaces. The helper-backed anti-amplification slice now closes `REQ-QUIC-RFC9000-S9P3P1-0001`, but the remaining S9/S9P1/S9P2/S9P3 requirements still need a connection-state machine before they can be closed cleanly.
- `9000-13-idle-and-close` is partially reusable at the helper layer, and the repo now has a connection close/drain lifecycle helper that closes the helper-backed no-send clauses for `REQ-QUIC-RFC9000-S10P2P2-0001` and `REQ-QUIC-RFC9000-S10P2P2-0003`. Idle-timeout floor and restart bookkeeping can be modeled independently, but silent close/state discard, immediate-close initiation, receive-triggered draining, and CONNECTION_CLOSE wire emission still need the endpoint runtime.
- `9000-14-stateless-reset` is partially reusable at the helper layer. The repo now closes the helper-backed packet-layout, token-generation, amplification-sizing, 38-bit visible-prefix, and matched-token drain/no-send clauses, but the explicit endpoint blockers remain `REQ-QUIC-RFC9000-S10P3-0001`, `REQ-QUIC-RFC9000-S10P3-0015`, token-retirement invalidation, token memory scoping by remote address, long-header reset policy, version-aware reset acceptance, and reset-send limiting, all of which still need the endpoint receive/send lifecycle surface.
- `9001-02-security-and-registry` is partially reusable at the helper layer. The helper-backed ceiling for the chunk closes `REQ-QUIC-RFC9001-S6-0002`, `REQ-QUIC-RFC9001-S8-0001`, and `REQ-QUIC-RFC9001-S10-0001` through `REQ-QUIC-RFC9001-S10-0003`. The remaining key-update and TLS handshake security clauses stay blocked until the repo has a handshake-confirmation/key-update surface, and `REQ-QUIC-RFC9001-S7-0001` plus `REQ-QUIC-RFC9001-S9-0001` stay deferred because they are policy/document-scope items rather than executable helper behavior.

## How To Use

- Add a gap here before implementation whenever RFC text leaves more than one plausible interpretation.
- Keep the note short and actionable.
- Reference the owning `SPEC-...` file and the follow-up artifact if one exists.
