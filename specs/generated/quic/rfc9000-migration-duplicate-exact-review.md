# RFC9000 Duplicate Exact-Statement Review

This is the first manual review slice after the RFC9000 migration crosswalk. It covers the duplicated exact-statement groups that the crosswalk intentionally left ambiguous.

## Inputs

- Crosswalk: `specs/generated/quic/rfc9000-requirement-migration-crosswalk.json`
- Governing plan: `C:/src/incursa/spec-trace/quic-rfc-migration-plan.md`
- Live requirement file: `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
- Staged source file: `C:/src/incursa/spec-trace/.work-rfc-batch/rfc9000/SPEC-QUIC-RFC9000.stable.json`

## Review Rule

Exact statement text remains the primary signal, but source-compatible RFC section context decides whether a staged clause can safely map to a live requirement. Identical statement text is not enough to collapse separate live section-keyed requirements.

## Summary

- Unique duplicated exact-statement groups reviewed: 5
- Live requirements reviewed: 12
- Source-compatible `preserve` mappings: 5
- Contextual live requirements preserved without staged replacement: 7
- Canonical requirement edits applied: 0
- Requirement identity changes applied: 0
- Retired-ID ledger updates required: 0

## Decisions

| Statement | Decision | Source-compatible staged mapping | Live IDs preserved without staged replacement |
| --- | --- | --- | --- |
| `MAX_STREAMS frames that do not increase the stream limit MUST be ignored.` | Preserve live IDs; do not collapse frame-encoding context. | `REQ-QUIC-RFC9000-S4P6-0011` -> `REQ-QUIC-RFC9000-0202` | `REQ-QUIC-RFC9000-S19P11-0008` |
| `The stateless reset token MUST be difficult to guess.` | Preserve live IDs; do not collapse generic stateless-reset and token-generation contexts. | `REQ-QUIC-RFC9000-S10P3P2-0001` -> `REQ-QUIC-RFC9000-0641` | `REQ-QUIC-RFC9000-S10P3-0016` |
| `Packets containing a zero value for this bit are not valid packets in this version and MUST be discarded.` | Preserve live IDs; staged clause is short-header scoped. | `REQ-QUIC-RFC9000-S17P3P1-0014` -> `REQ-QUIC-RFC9000-1069` | `REQ-QUIC-RFC9000-S17P2-0015` |
| `The value included prior to protection MUST be set to 0.` | Preserve both live IDs with source-compatible staged mappings. | `REQ-QUIC-RFC9000-S17P2-0028` -> `REQ-QUIC-RFC9000-1730`; `REQ-QUIC-RFC9000-S17P3P1-0016` -> `REQ-QUIC-RFC9000-1072` | None |
| `The Length field MUST be encoded as a variable-length integer.` | Preserve live IDs; staged clause is too broad to replace packet/frame-specific proof owners. | None | `REQ-QUIC-RFC9000-S17P2P2-0013`, `REQ-QUIC-RFC9000-S17P2P3-0015`, `REQ-QUIC-RFC9000-S17P2P4-0014`, `REQ-QUIC-RFC9000-S19P6-0006` |

## Result

This slice converts the duplicated exact-statement ambiguity into reviewed preserve decisions. No canonical requirement edit is needed because every reviewed live requirement keeps its current ID, and no staged deterministic ID becomes canonical.

## Next Review Target

Review no-exact-statement live rows by section cluster, starting with RFC9000 section 2 stream abstraction rows. Those rows are likely wording-preserve candidates rather than missing behavior, but they require semantic comparison instead of exact text matching.
