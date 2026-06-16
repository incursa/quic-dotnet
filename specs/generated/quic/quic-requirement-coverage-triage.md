# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 2577 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 0 |
| partially_covered | 0 |
| uncovered_blocked | 64 |
| uncovered_unblocked | 0 |

| Work queue tag | Count |
| --- | ---: |
| clean | 2577 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 0 |
| new_tests_needed | 64 |
| blocked | 64 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 0 requirements. Examples: .
- Restructure-needed proof: 0 requirements. Examples: .
- New proof or implementation work: 64 requirements. Examples: .
- Blocked by recorded gap families: 64 requirements. Examples: REQ-QUIC-RFC9484-0150, REQ-QUIC-RFC9484-0151, REQ-QUIC-RFC9484-0152, REQ-QUIC-RFC9484-0153, REQ-QUIC-RFC9484-0154, REQ-QUIC-RFC9484-0155, REQ-QUIC-RFC9484-0156, REQ-QUIC-RFC9484-0157, REQ-QUIC-RFC9484-0158, REQ-QUIC-RFC9484-0159, REQ-QUIC-RFC9484-0160, REQ-QUIC-RFC9484-0161.

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
| RFC9297 | 84 | 84 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9298 | 117 | 117 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9308 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9312 | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9368 | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9369 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9461 | 38 | 38 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9463 | 116 | 116 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9464 | 76 | 76 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9484 | 213 | 149 | 0 | 0 | 0 | 0 | 64 | 0 |
