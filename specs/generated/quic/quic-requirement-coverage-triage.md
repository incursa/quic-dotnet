# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 411 |
| covered_but_missing_xrefs | 23 |
| covered_but_proof_too_broad | 353 |
| partially_covered | 104 |
| uncovered_blocked | 266 |
| uncovered_unblocked | 574 |

| Work queue tag | Count |
| --- | ---: |
| clean | 416 |
| metadata_only | 23 |
| restructure_needed | 419 |
| new_tests_needed | 1277 |
| blocked | 266 |

## Queue

- Metadata-only fixes: 23 requirements. Examples: REQ-QUIC-RFC9000-S19P21-0002, REQ-QUIC-RFC9000-S19P21-0003, REQ-QUIC-RFC9000-S3P2-0002, REQ-QUIC-RFC9000-S3P2-0006, REQ-QUIC-RFC9000-S3P2-0007, REQ-QUIC-RFC9000-S3P2-0008, REQ-QUIC-RFC9000-S3P2-0012, REQ-QUIC-RFC9000-S3P2-0014.
- Restructure-needed proof: 419 requirements. Examples: REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S13P1-0003, REQ-QUIC-RFC9000-S13P2-0001, REQ-QUIC-RFC9000-S13P2-0002, REQ-QUIC-RFC9000-S13P2-0003, REQ-QUIC-RFC9000-S13P2-0004, REQ-QUIC-RFC9000-S13P2P1-0002, REQ-QUIC-RFC9000-S13P2P1-0004.
- New proof or implementation work: 1277 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P3P2-0010, REQ-QUIC-RFC9000-S10P3P2-0012, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11-0005, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S11P1-0004, REQ-QUIC-RFC9000-S11P1-0005, REQ-QUIC-RFC9000-S11P1-0006.
- Blocked by recorded gap families: 266 requirements. Examples: REQ-QUIC-RFC9000-S10-0001, REQ-QUIC-RFC9000-S10-0002, REQ-QUIC-RFC9000-S10P2-0001, REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0004, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0006, REQ-QUIC-RFC9000-S10P2-0007, REQ-QUIC-RFC9000-S10P2-0008, REQ-QUIC-RFC9000-S10P2-0009, REQ-QUIC-RFC9000-S10P2-0010.

## RFC Breakdown

| RFC | Total | trace_clean | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 228 | 13 | 322 | 97 | 218 | 565 |
| RFC9001 | 61 | 5 | 0 | 7 | 7 | 33 | 9 |
| RFC9002 | 224 | 175 | 10 | 24 | 0 | 15 | 0 |
