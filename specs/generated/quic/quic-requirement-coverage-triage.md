# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 1733 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 0 |
| partially_covered | 0 |
| uncovered_blocked | 38 |
| uncovered_unblocked | 0 |

| Work queue tag | Count |
| --- | ---: |
| clean | 1733 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 0 |
| new_tests_needed | 38 |
| blocked | 38 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes:  requirements. Examples: .
- Restructure-needed proof:  requirements. Examples: .
- New proof or implementation work: 38 requirements. Examples: .
- Blocked by recorded gap families: 38 requirements. Examples: REQ-QUIC-RFC9000-S19P21-0004, REQ-QUIC-RFC9000-S19P21-0005, REQ-QUIC-RFC9000-S19P21-0006, REQ-QUIC-RFC9000-S19P21-0007, REQ-QUIC-RFC9000-S19P21-0008, REQ-QUIC-RFC9000-S19P21-0009, REQ-QUIC-RFC9000-S19P21-0010, REQ-QUIC-RFC9000-S21P5-0001, REQ-QUIC-RFC9000-S21P5-0002, REQ-QUIC-RFC9000-S21P5-0003, REQ-QUIC-RFC9000-S21P5P6-0002, REQ-QUIC-RFC9000-S21P5P6-0003.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 1405 | 0 | 0 | 0 | 0 | 38 | 0 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
