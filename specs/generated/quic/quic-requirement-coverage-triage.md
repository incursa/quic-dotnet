# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 476 |
| covered_but_missing_xrefs | 124 |
| covered_but_proof_too_broad | 179 |
| partially_covered | 258 |
| uncovered_blocked | 149 |
| uncovered_unblocked | 550 |

| Work queue tag | Count |
| --- | ---: |
| clean | 476 |
| metadata_only | 124 |
| restructure_needed | 240 |
| new_tests_needed | 1123 |
| blocked | 149 |

## Queue

- Metadata-only fixes: 124 requirements. Examples: REQ-QUIC-RFC9000-S17P2-0021, REQ-QUIC-RFC9000-S17P2P1-0005, REQ-QUIC-RFC9000-S17P2P4-0001, REQ-QUIC-RFC9000-S17P2P4-0002, REQ-QUIC-RFC9000-S17P3P1-0007, REQ-QUIC-RFC9000-S18P1-0002, REQ-QUIC-RFC9000-S18P2-0004, REQ-QUIC-RFC9000-S19P1-0004, REQ-QUIC-RFC9000-S19P1-0005, REQ-QUIC-RFC9000-S19P12-0005, REQ-QUIC-RFC9000-S19P16-0006, REQ-QUIC-RFC9000-S19P17-0003.
- Restructure-needed proof: 240 requirements. Examples: REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S13P2P3-0002, REQ-QUIC-RFC9000-S13P2P3-0003, REQ-QUIC-RFC9000-S13P2P3-0004, REQ-QUIC-RFC9000-S13P2P3-0007, REQ-QUIC-RFC9000-S13P2P3-0008, REQ-QUIC-RFC9000-S13P2P3-0009, REQ-QUIC-RFC9000-S13P2P3-0010.
- New proof or implementation work: 1123 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P3P2-0010, REQ-QUIC-RFC9000-S10P3P2-0012, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S11P1-0007, REQ-QUIC-RFC9000-S11P1-0008, REQ-QUIC-RFC9000-S12P1-0001, REQ-QUIC-RFC9000-S12P1-0002.
- Blocked by recorded gap families: 149 requirements. Examples: REQ-QUIC-RFC9000-S10-0001, REQ-QUIC-RFC9000-S10-0002, REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0007, REQ-QUIC-RFC9000-S10P2-0008, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P1-0001, REQ-QUIC-RFC9000-S10P2P1-0002, REQ-QUIC-RFC9000-S10P2P1-0003.

## RFC Breakdown

| RFC | Total | trace_clean | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 288 | 91 | 178 | 215 | 122 | 549 |
| RFC9001 | 61 | 9 | 20 | 0 | 15 | 17 | 0 |
| RFC9002 | 224 | 171 | 13 | 1 | 28 | 10 | 1 |
