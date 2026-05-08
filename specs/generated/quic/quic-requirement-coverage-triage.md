# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 1480 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 55 |
| covered_but_proof_too_broad | 6 |
| partially_covered | 54 |
| uncovered_blocked | 54 |
| uncovered_unblocked | 122 |

| Work queue tag | Count |
| --- | ---: |
| clean | 1480 |
| coverage_contract_needed | 0 |
| metadata_only | 55 |
| restructure_needed | 13 |
| new_tests_needed | 232 |
| blocked | 54 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 55 requirements. Examples: REQ-QUIC-RFC9000-S19P16-0011, REQ-QUIC-RFC9000-S20P1-0002, REQ-QUIC-RFC9000-S20P1-0003, REQ-QUIC-RFC9000-S20P1-0004, REQ-QUIC-RFC9000-S20P1-0005, REQ-QUIC-RFC9000-S20P1-0006, REQ-QUIC-RFC9000-S20P1-0007, REQ-QUIC-RFC9000-S20P1-0008, REQ-QUIC-RFC9000-S21P12-0001, REQ-QUIC-RFC9000-S21P12-0002, REQ-QUIC-RFC9000-S21P1P1P1-0002, REQ-QUIC-RFC9000-S22P5-0001.
- Restructure-needed proof: 13 requirements. Examples: REQ-QUIC-RFC9000-S13P3-0010, REQ-QUIC-RFC9000-S13P4P1-0006, REQ-QUIC-RFC9000-S13P4P2-0006, REQ-QUIC-RFC9000-S13P4P2P1-0001, REQ-QUIC-RFC9000-S13P4P2P1-0004, REQ-QUIC-RFC9000-S13P4P2P1-0005, REQ-QUIC-RFC9000-S13P4P2P2-0001, REQ-QUIC-RFC9000-S13P4P2P2-0004, REQ-QUIC-RFC9000-S2-0006, REQ-QUIC-RFC9000-S2-0008, REQ-QUIC-RFC9000-S5P2P3-0002, REQ-QUIC-RFC9000-S5P2P3-0004.
- New proof or implementation work: 232 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P2P1-0006, REQ-QUIC-RFC9000-S10P2P1-0009, REQ-QUIC-RFC9000-S12P2-0009, REQ-QUIC-RFC9000-S12P3-0007, REQ-QUIC-RFC9000-S12P3-0008, REQ-QUIC-RFC9000-S12P4-0007, REQ-QUIC-RFC9000-S12P5-0007, REQ-QUIC-RFC9000-S13P2P6-0001, REQ-QUIC-RFC9000-S13P3-0006, REQ-QUIC-RFC9000-S13P3-0010, REQ-QUIC-RFC9000-S13P3-0026.
- Blocked by recorded gap families: 54 requirements. Examples: REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P3-0002, REQ-QUIC-RFC9000-S10P2P3-0007, REQ-QUIC-RFC9000-S10P2P3-0009, REQ-QUIC-RFC9000-S10P3P1-0004, REQ-QUIC-RFC9000-S10P3P1-0005, REQ-QUIC-RFC9000-S10P3P1-0006, REQ-QUIC-RFC9000-S10P3P1-0007.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 1152 | 0 | 55 | 6 | 54 | 54 | 122 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9002 | 224 | 224 | 0 | 0 | 0 | 0 | 0 | 0 |
