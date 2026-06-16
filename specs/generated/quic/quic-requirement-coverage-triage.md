# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 2048 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 0 |
| partially_covered | 0 |
| uncovered_blocked | 593 |
| uncovered_unblocked | 0 |

| Work queue tag | Count |
| --- | ---: |
| clean | 2048 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 0 |
| new_tests_needed | 593 |
| blocked | 593 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 0 requirements. Examples: .
- Restructure-needed proof: 0 requirements. Examples: .
- New proof or implementation work: 593 requirements. Examples: .
- Blocked by recorded gap families: 593 requirements. Examples: REQ-QUIC-RFC9297-0001, REQ-QUIC-RFC9297-0002, REQ-QUIC-RFC9297-0003, REQ-QUIC-RFC9297-0004, REQ-QUIC-RFC9297-0005, REQ-QUIC-RFC9297-0006, REQ-QUIC-RFC9297-0007, REQ-QUIC-RFC9297-0008, REQ-QUIC-RFC9297-0009, REQ-QUIC-RFC9297-0010, REQ-QUIC-RFC9297-0011, REQ-QUIC-RFC9297-0012.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1451 | 1451 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9114 | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9204 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9220 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9221 | 33 | 33 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9250 | 141 | 141 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9287 | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9297 | 84 | 0 | 0 | 0 | 0 | 0 | 84 | 0 |
| RFC9298 | 117 | 0 | 0 | 0 | 0 | 0 | 117 | 0 |
| RFC9308 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9312 | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9368 | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9369 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9461 | 38 | 9 | 0 | 0 | 0 | 0 | 29 | 0 |
| RFC9463 | 116 | 15 | 0 | 0 | 0 | 0 | 101 | 0 |
| RFC9464 | 76 | 27 | 0 | 0 | 0 | 0 | 49 | 0 |
| RFC9484 | 213 | 0 | 0 | 0 | 0 | 0 | 213 | 0 |
