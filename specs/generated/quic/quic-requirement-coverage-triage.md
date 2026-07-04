# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 2615 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 0 |
| covered_but_proof_too_broad | 4 |
| partially_covered | 58 |
| uncovered_blocked | 1 |
| uncovered_unblocked | 0 |

| Work queue tag | Count |
| --- | ---: |
| clean | 2615 |
| coverage_contract_needed | 0 |
| metadata_only | 0 |
| restructure_needed | 4 |
| new_tests_needed | 63 |
| blocked | 1 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 0 requirements. Examples: .
- Restructure-needed proof: 4 requirements. Examples: RFC9000-S7-2-P2-S2-R01, RFC9297-S3-3-P1-R01, RFC9297-S3-3-P2-S1-R01, RFC9297-S3-3-P3-R01.
- New proof or implementation work: 63 requirements. Examples: RFC9000-S11-1-P5-S1-R01, RFC9000-S11-1-P5-S3-R01, RFC9000-S14-1-P1-S3-R01, RFC9000-S14-2-P2-S1-R01, RFC9000-S2-2-P6-R01, RFC9000-S21-11-P2-R01, RFC9000-S21-11-P3-R01, RFC9000-S4-5-P4-R01, RFC9000-S4-5-P5-S2-R01, RFC9000-S7-2-P2-S2-R01, RFC9000-S7-4-P7-R01, RFC9000-S7-5-P3-S3-R01.
- Blocked by recorded gap families: 1 requirements. Examples: RFC9368-S4-P3-S2-R01.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1450 | 1433 | 0 | 0 | 1 | 16 | 0 | 0 |
| RFC9001 | 96 | 95 | 0 | 0 | 0 | 1 | 0 | 0 |
| RFC9002 | 226 | 223 | 0 | 0 | 0 | 3 | 0 | 0 |
| RFC9114 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9204 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9220 | 31 | 31 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9221 | 33 | 33 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9250 | 141 | 135 | 0 | 0 | 0 | 6 | 0 | 0 |
| RFC9287 | 4 | 4 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9297 | 84 | 72 | 0 | 0 | 3 | 9 | 0 | 0 |
| RFC9298 | 117 | 94 | 0 | 0 | 0 | 23 | 0 | 0 |
| RFC9308 | 10 | 10 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9312 | 5 | 5 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9368 | 7 | 6 | 0 | 0 | 0 | 0 | 1 | 0 |
| RFC9369 | 3 | 3 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9461 | 42 | 42 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9463 | 120 | 120 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9464 | 77 | 77 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9484 | 213 | 213 | 0 | 0 | 0 | 0 | 0 | 0 |
