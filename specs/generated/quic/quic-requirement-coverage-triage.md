# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 1779 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 0 |
| partially_covered | 0 |
| uncovered_blocked | 0 |
| uncovered_unblocked | 0 |

| Work queue tag | Count |
| --- | ---: |
| clean | 1779 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 0 |
| new_tests_needed | 0 |
| blocked | 0 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes:  requirements. Examples: .
- Restructure-needed proof:  requirements. Examples: .
- New proof or implementation work:  requirements. Examples: .
- Blocked by recorded gap families: 0 requirements. Examples: .

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1451 | 1451 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
