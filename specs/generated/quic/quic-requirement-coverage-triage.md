# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 585 |
| covered_but_missing_xrefs | 81 |
| covered_but_proof_too_broad | 179 |
| partially_covered | 295 |
| uncovered_blocked | 149 |
| uncovered_unblocked | 447 |

| Work queue tag | Count |
| --- | ---: |
| clean | 585 |
| metadata_only | 81 |
| restructure_needed | 240 |
| new_tests_needed | 1057 |
| blocked | 149 |

## Queue

- Metadata-only fixes: 81 requirements. Examples: REQ-QUIC-RFC9000-S3P2-0005, REQ-QUIC-RFC9000-S3P2-0008, REQ-QUIC-RFC9000-S3P2-0012, REQ-QUIC-RFC9000-S3P2-0013, REQ-QUIC-RFC9000-S3P2-0014, REQ-QUIC-RFC9000-S3P2-0019, REQ-QUIC-RFC9000-S3P2-0020, REQ-QUIC-RFC9000-S3P2-0022, REQ-QUIC-RFC9000-S3P2-0023, REQ-QUIC-RFC9000-S3P2-0024, REQ-QUIC-RFC9000-S3P5-0010, REQ-QUIC-RFC9000-S3P5-0012.
- Restructure-needed proof: 240 requirements. Examples: REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S13P2P3-0002, REQ-QUIC-RFC9000-S13P2P3-0003, REQ-QUIC-RFC9000-S13P2P3-0004, REQ-QUIC-RFC9000-S13P2P3-0007, REQ-QUIC-RFC9000-S13P2P3-0008, REQ-QUIC-RFC9000-S13P2P3-0009, REQ-QUIC-RFC9000-S13P2P3-0010.
- New proof or implementation work: 1057 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P3P2-0010, REQ-QUIC-RFC9000-S10P3P2-0012, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S11P1-0007, REQ-QUIC-RFC9000-S11P1-0008, REQ-QUIC-RFC9000-S12P1-0001, REQ-QUIC-RFC9000-S12P1-0002.
- Blocked by recorded gap families: 149 requirements. Examples: REQ-QUIC-RFC9000-S10-0001, REQ-QUIC-RFC9000-S10-0002, REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0007, REQ-QUIC-RFC9000-S10P2-0008, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P1-0001, REQ-QUIC-RFC9000-S10P2P1-0002, REQ-QUIC-RFC9000-S10P2P1-0003.

## RFC Breakdown

| RFC | Total | trace_clean | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 392 | 53 | 178 | 252 | 122 | 446 |
| RFC9001 | 61 | 13 | 16 | 0 | 15 | 17 | 0 |
| RFC9002 | 224 | 172 | 12 | 1 | 28 | 10 | 1 |
