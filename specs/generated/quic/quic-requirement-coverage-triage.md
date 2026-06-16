# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 2003 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 0 |
| partially_covered | 10 |
| uncovered_blocked | 628 |
| uncovered_unblocked | 0 |

| Work queue tag | Count |
| --- | ---: |
| clean | 2003 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 10 |
| new_tests_needed | 638 |
| blocked | 628 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 0 requirements. Examples: .
- Restructure-needed proof: 10 requirements. Examples: REQ-QUIC-RFC9463-0009, REQ-QUIC-RFC9463-0010, REQ-QUIC-RFC9463-0022, REQ-QUIC-RFC9463-0025, REQ-QUIC-RFC9463-0083, REQ-QUIC-RFC9463-0086, REQ-QUIC-RFC9463-0087, REQ-QUIC-RFC9463-0112, REQ-QUIC-RFC9463-0114, REQ-QUIC-RFC9463-0116.
- New proof or implementation work: 638 requirements. Examples: REQ-QUIC-RFC9463-0009, REQ-QUIC-RFC9463-0010, REQ-QUIC-RFC9463-0022, REQ-QUIC-RFC9463-0025, REQ-QUIC-RFC9463-0083, REQ-QUIC-RFC9463-0086, REQ-QUIC-RFC9463-0087, REQ-QUIC-RFC9463-0112, REQ-QUIC-RFC9463-0114, REQ-QUIC-RFC9463-0116.
- Blocked by recorded gap families: 628 requirements. Examples: REQ-QUIC-RFC9220-0001, REQ-QUIC-RFC9220-0002, REQ-QUIC-RFC9220-0003, REQ-QUIC-RFC9220-0004, REQ-QUIC-RFC9220-0005, REQ-QUIC-RFC9220-0006, REQ-QUIC-RFC9220-0007, REQ-QUIC-RFC9220-0008, REQ-QUIC-RFC9297-0001, REQ-QUIC-RFC9297-0002, REQ-QUIC-RFC9297-0003, REQ-QUIC-RFC9297-0004.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1451 | 1451 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9114 | 7 | 7 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9204 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9220 | 8 | 0 | 0 | 0 | 0 | 0 | 8 | 0 |
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
| RFC9463 | 116 | 5 | 0 | 0 | 0 | 10 | 101 | 0 |
| RFC9464 | 76 | 0 | 0 | 0 | 0 | 0 | 76 | 0 |
| RFC9484 | 213 | 0 | 0 | 0 | 0 | 0 | 213 | 0 |
