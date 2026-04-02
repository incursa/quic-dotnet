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

## How To Use

- Add a gap here before implementation whenever RFC text leaves more than one plausible interpretation.
- Keep the note short and actionable.
- Reference the owning `SPEC-...` file and the follow-up artifact if one exists.
