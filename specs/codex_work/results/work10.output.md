Refreshed the QUIC requirement coverage triage outputs in:
- [specs/generated/quic/quic-requirement-coverage-triage.json](C:/src/incursa/quic-dotnet/specs/generated/quic/quic-requirement-coverage-triage.json)
- [specs/generated/quic/quic-requirement-coverage-triage.md](C:/src/incursa/quic-dotnet/specs/generated/quic/quic-requirement-coverage-triage.md)

What changed in the regenerated report:
- Overall totals: 1,736 requirements total; `trace_clean` 116; `covered_but_missing_xrefs` 6; `covered_but_proof_too_broad` 356; `partially_covered` 130; `uncovered_blocked` 314; `uncovered_unblocked` 814.
- RFC 9000 totals: 1,443 total; `trace_clean` 74; `covered_but_missing_xrefs` 4; `covered_but_proof_too_broad` 306; `partially_covered` 90; `uncovered_blocked` 266; `uncovered_unblocked` 703.

Targeted `S17P2P1` subsection:
- `REQ-QUIC-RFC9000-S17P2P1-0003` is `covered_but_missing_xrefs`.
- `REQ-QUIC-RFC9000-S17P2P1-0005` and `REQ-QUIC-RFC9000-S17P2P1-0013` are `trace_clean`.
- `REQ-QUIC-RFC9000-S17P2P1-0004` and `REQ-QUIC-RFC9000-S17P2P1-0019` remain `covered_but_proof_too_broad`.
- `REQ-QUIC-RFC9000-S17P2P1-0006`, `REQ-QUIC-RFC9000-S17P2P1-0007`, `REQ-QUIC-RFC9000-S17P2P1-0008`, and `REQ-QUIC-RFC9000-S17P2P1-0009` moved to `partially_covered`.
- The remaining 11 requirements in the subsection are still `uncovered_unblocked`.

Assessment:
- The chosen subsection improved cleanly enough to justify another narrow overnight slice. The refresh converted four requirements from broad/partial mixed proof into partially covered focused proof, and the RFC 9000 wide totals moved in the right direction.
- It is not ready to call the subsection clean yet. The next slice should stay tightly on the remaining `S17P2P1` gaps, especially the two broad-only requirements and the missing proof kinds on the four partially covered ones.
