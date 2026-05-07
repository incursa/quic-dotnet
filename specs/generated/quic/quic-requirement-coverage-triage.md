# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 1363 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 44 |
| covered_but_proof_too_broad | 40 |
| partially_covered | 108 |
| uncovered_blocked | 71 |
| uncovered_unblocked | 145 |

| Work queue tag | Count |
| --- | ---: |
| clean | 1363 |
| coverage_contract_needed | 0 |
| metadata_only | 44 |
| restructure_needed | 52 |
| new_tests_needed | 359 |
| blocked | 71 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 44 requirements. Examples: REQ-QUIC-RFC9000-S10P2P1-0004, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S12P1-0005, REQ-QUIC-RFC9000-S12P1-0006, REQ-QUIC-RFC9000-S12P1-0007, REQ-QUIC-RFC9000-S12P2-0008, REQ-QUIC-RFC9000-S12P3-0009, REQ-QUIC-RFC9000-S12P3-0010, REQ-QUIC-RFC9000-S13P2-0001, REQ-QUIC-RFC9000-S17P2P4-0003, REQ-QUIC-RFC9000-S17P2P4-0017, REQ-QUIC-RFC9000-S17P2P4-0019.
- Restructure-needed proof: 52 requirements. Examples: REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S13P2P3-0002, REQ-QUIC-RFC9000-S13P2P3-0003, REQ-QUIC-RFC9000-S13P2P3-0004, REQ-QUIC-RFC9000-S13P2P3-0007, REQ-QUIC-RFC9000-S13P2P3-0008, REQ-QUIC-RFC9000-S13P2P3-0009, REQ-QUIC-RFC9000-S13P2P3-0010, REQ-QUIC-RFC9000-S13P2P3-0011, REQ-QUIC-RFC9000-S13P2P3-0012, REQ-QUIC-RFC9000-S13P2P5-0002.
- New proof or implementation work: 359 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P2P1-0006, REQ-QUIC-RFC9000-S10P2P1-0009, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0007, REQ-QUIC-RFC9000-S11P1-0008, REQ-QUIC-RFC9000-S12P2-0009, REQ-QUIC-RFC9000-S12P3-0007, REQ-QUIC-RFC9000-S12P3-0008, REQ-QUIC-RFC9000-S12P4-0007, REQ-QUIC-RFC9000-S12P5-0007.
- Blocked by recorded gap families: 71 requirements. Examples: REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P3-0002, REQ-QUIC-RFC9000-S10P2P3-0007, REQ-QUIC-RFC9000-S10P2P3-0009, REQ-QUIC-RFC9000-S10P3P1-0004, REQ-QUIC-RFC9000-S10P3P1-0005, REQ-QUIC-RFC9000-S10P3P1-0006, REQ-QUIC-RFC9000-S10P3P1-0007.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 1050 | 0 | 44 | 40 | 108 | 56 | 145 |
| RFC9001 | 96 | 81 | 0 | 0 | 0 | 0 | 15 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
