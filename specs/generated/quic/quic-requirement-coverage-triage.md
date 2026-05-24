# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 1785 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 6 |
| partially_covered | 14 |
| uncovered_blocked | 0 |
| uncovered_unblocked | 7 |

| Work queue tag | Count |
| --- | ---: |
| clean | 1785 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 12 |
| new_tests_needed | 27 |
| blocked | 0 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes:  requirements. Examples: .
- Restructure-needed proof: 12 requirements. Examples: REQ-QUIC-RFC9221-S3-0001, REQ-QUIC-RFC9221-S3-0002, REQ-QUIC-RFC9221-S3-0003, REQ-QUIC-RFC9221-S3-0008, REQ-QUIC-RFC9221-S3-0009, REQ-QUIC-RFC9221-S3-0010, REQ-QUIC-RFC9221-S4-0001, REQ-QUIC-RFC9221-S4-0002, REQ-QUIC-RFC9221-S4-0003, REQ-QUIC-RFC9221-S4-0004, REQ-QUIC-RFC9221-S4-0005, REQ-QUIC-RFC9221-S4-0006.
- New proof or implementation work: 27 requirements. Examples: REQ-QUIC-RFC9221-S3-0001, REQ-QUIC-RFC9221-S3-0002, REQ-QUIC-RFC9221-S3-0003, REQ-QUIC-RFC9221-S3-0004, REQ-QUIC-RFC9221-S3-0005, REQ-QUIC-RFC9221-S3-0006, REQ-QUIC-RFC9221-S3-0007, REQ-QUIC-RFC9221-S3-0008, REQ-QUIC-RFC9221-S3-0009, REQ-QUIC-RFC9221-S3-0010, REQ-QUIC-RFC9221-S3-0011, REQ-QUIC-RFC9221-S4-0001.
- Blocked by recorded gap families: 0 requirements. Examples: .

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1451 | 1451 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9221 | 33 | 6 | 0 | 0 | 6 | 14 | 0 | 7 |
