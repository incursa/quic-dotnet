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

- `9000-19-retransmission-and-frame-reliability` is split across send-path, recovery, stream-lifecycle, flow-control, path-validation, connection-ID, and congestion-control behaviors that are not present in the current helper-only transport slice. The implemented subset is limited to ACK freshness and PATH_CHALLENGE payload uniqueness; the remaining S13P3 requirements stay blocked until a sender/recovery architecture exists.
- `9000-02-stream-state` is greenfield. The repository does not yet have a connection-scoped stream abstraction, ordered receive buffering, stream-level flow control, or stop-sending/reset coordination, so the S3/S3P1/S3P2/S3P3/S3P4/S3P5 requirements remain blocked until those transport layers exist.
- `9000-03-flow-control` is partially reusable at the wire layer, but the repository still lacks the connection-scoped flow-control and stream-credit accounting needed to close the S4/S4P1/S4P2/S4P4/S4P5/S4P6 behavioral requirements cleanly. The current slice can validate and round-trip transport-parameter and frame encodings, but it cannot yet apply advertised credit, enforce limits, track final sizes, or emit the required flow-control errors without the missing stream-state substrate.
- `9000-11-migration-core` is mostly blocked by the absence of connection-migration orchestration, path-selection, packet-sending, and ECN/timer surfaces. The helper layer can limit sends on an unvalidated peer address, but the remaining S9/S9P1/S9P2/S9P3 requirements need a connection-state machine before they can be closed cleanly.
- `9000-13-idle-and-close` is partially reusable at the helper layer, but the silent-close, immediate-close, and draining-state requirements remain blocked until the repo has a connection-state machine and `CONNECTION_CLOSE` wire support. Idle-timeout floor and restart bookkeeping can be modeled independently, but the close/drain lifecycle cannot be completed in the current slice.

## How To Use

- Add a gap here before implementation whenever RFC text leaves more than one plausible interpretation.
- Keep the note short and actionable.
- Reference the owning `SPEC-...` file and the follow-up artifact if one exists.
