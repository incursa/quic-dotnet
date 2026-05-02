# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 786 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 51 |
| covered_but_proof_too_broad | 154 |
| partially_covered | 302 |
| uncovered_blocked | 96 |
| uncovered_unblocked | 382 |

| Work queue tag | Count |
| --- | ---: |
| clean | 786 |
| coverage_contract_needed | 0 |
| metadata_only | 51 |
| restructure_needed | 232 |
| new_tests_needed | 922 |
| blocked | 96 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 51 requirements. Examples: REQ-QUIC-RFC9000-S18P2-0002, REQ-QUIC-RFC9000-S19P19-0012, REQ-QUIC-RFC9000-S19P19-0017, REQ-QUIC-RFC9000-S3P2-0013, REQ-QUIC-RFC9000-S3P2-0014, REQ-QUIC-RFC9000-S3P2-0019, REQ-QUIC-RFC9000-S3P2-0020, REQ-QUIC-RFC9000-S4-0005, REQ-QUIC-RFC9000-S4P5-0005, REQ-QUIC-RFC9000-S4P5-0006, REQ-QUIC-RFC9000-S4P5-0008, REQ-QUIC-RFC9000-S4P6-0002.
- Restructure-needed proof: 232 requirements. Examples: REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S13P2P3-0002, REQ-QUIC-RFC9000-S13P2P3-0003, REQ-QUIC-RFC9000-S13P2P3-0004, REQ-QUIC-RFC9000-S13P2P3-0007, REQ-QUIC-RFC9000-S13P2P3-0008, REQ-QUIC-RFC9000-S13P2P3-0009, REQ-QUIC-RFC9000-S13P2P3-0010.
- New proof or implementation work: 922 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P3P2-0010, REQ-QUIC-RFC9000-S10P3P2-0012, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S11P1-0007, REQ-QUIC-RFC9000-S11P1-0008, REQ-QUIC-RFC9000-S12P1-0001, REQ-QUIC-RFC9000-S12P1-0002.
- Blocked by recorded gap families: 96 requirements. Examples: REQ-QUIC-RFC9000-S10-0001, REQ-QUIC-RFC9000-S10-0002, REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0007, REQ-QUIC-RFC9000-S10P2-0008, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P1-0001, REQ-QUIC-RFC9000-S10P2P1-0002, REQ-QUIC-RFC9000-S10P2P1-0003.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 518 | 0 | 42 | 153 | 269 | 79 | 382 |
| RFC9001 | 96 | 80 | 0 | 0 | 0 | 1 | 15 | 0 |
| RFC9002 | 224 | 180 | 0 | 9 | 1 | 32 | 2 | 0 |
