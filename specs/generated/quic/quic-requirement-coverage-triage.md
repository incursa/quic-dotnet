# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 833 |
| missing_coverage_contract | 0 |
| covered_but_missing_xrefs | 78 |
| covered_but_proof_too_broad | 146 |
| partially_covered | 316 |
| uncovered_blocked | 81 |
| uncovered_unblocked | 317 |

| Work queue tag | Count |
| --- | ---: |
| clean | 833 |
| coverage_contract_needed | 0 |
| metadata_only | 78 |
| restructure_needed | 228 |
| new_tests_needed | 850 |
| blocked | 81 |

## Queue

- Missing coverage contracts: 0 requirements. Examples: .
- Metadata-only fixes: 78 requirements. Examples: REQ-QUIC-RFC9000-S10P2P1-0004, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S12P1-0001, REQ-QUIC-RFC9000-S12P1-0002, REQ-QUIC-RFC9000-S12P1-0003, REQ-QUIC-RFC9000-S12P1-0004, REQ-QUIC-RFC9000-S12P1-0005, REQ-QUIC-RFC9000-S12P1-0006, REQ-QUIC-RFC9000-S12P1-0007, REQ-QUIC-RFC9000-S12P2-0008, REQ-QUIC-RFC9000-S12P3-0009, REQ-QUIC-RFC9000-S12P3-0010.
- Restructure-needed proof: 228 requirements. Examples: REQ-QUIC-RFC9000-S10P2P3-0006, REQ-QUIC-RFC9000-S10P2P3-0011, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S13P2P3-0002, REQ-QUIC-RFC9000-S13P2P3-0003, REQ-QUIC-RFC9000-S13P2P3-0004, REQ-QUIC-RFC9000-S13P2P3-0007, REQ-QUIC-RFC9000-S13P2P3-0008, REQ-QUIC-RFC9000-S13P2P3-0009, REQ-QUIC-RFC9000-S13P2P3-0010, REQ-QUIC-RFC9000-S13P2P3-0011.
- New proof or implementation work: 850 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P2P1-0006, REQ-QUIC-RFC9000-S10P2P1-0009, REQ-QUIC-RFC9000-S10P2P3-0006, REQ-QUIC-RFC9000-S10P2P3-0011, REQ-QUIC-RFC9000-S10P3P2-0010, REQ-QUIC-RFC9000-S10P3P2-0012, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0007, REQ-QUIC-RFC9000-S11P1-0008, REQ-QUIC-RFC9000-S12P2-0009.
- Blocked by recorded gap families: 81 requirements. Examples: REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P3-0001, REQ-QUIC-RFC9000-S10P2P3-0002, REQ-QUIC-RFC9000-S10P2P3-0003, REQ-QUIC-RFC9000-S10P2P3-0004, REQ-QUIC-RFC9000-S10P2P3-0005, REQ-QUIC-RFC9000-S10P2P3-0007, REQ-QUIC-RFC9000-S10P2P3-0008.

## RFC Breakdown

| RFC | Total | trace_clean | missing_coverage_contract | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 557 | 0 | 70 | 145 | 290 | 64 | 317 |
| RFC9001 | 96 | 80 | 0 | 0 | 0 | 1 | 15 | 0 |
| RFC9002 | 224 | 188 | 0 | 8 | 1 | 25 | 2 | 0 |
