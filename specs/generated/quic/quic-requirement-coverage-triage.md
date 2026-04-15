# QUIC Requirement Coverage Triage

## Sources

- Canonical specs: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`, `SPEC-QUIC-RFC9000.json`, `SPEC-QUIC-RFC9001.json`, `SPEC-QUIC-RFC9002.json`.
- Deferral and blocker ledger: `specs/requirements/quic/REQUIREMENT-GAPS.md`.
- Test evidence: executable methods under `tests/Incursa.Quic.Tests`, including requirement-owned homes; empty scaffolds still contribute no evidence.
- Evidence tags: `RequirementAttribute`, `Trait("Category", ...)`, and any canonical `trace.x_test_refs` that still resolve to source.

## Summary

| State | Count |
| --- | ---: |
| trace_clean | 368 |
| covered_but_missing_xrefs | 131 |
| covered_but_proof_too_broad | 180 |
| partially_covered | 226 |
| uncovered_blocked | 225 |
| uncovered_unblocked | 606 |

| Work queue tag | Count |
| --- | ---: |
| clean | 368 |
| metadata_only | 131 |
| restructure_needed | 242 |
| new_tests_needed | 1223 |
| blocked | 225 |

## Queue

- Metadata-only fixes: 131 requirements. Examples: REQ-QUIC-RFC9000-S10P3-0010, REQ-QUIC-RFC9000-S10P3-0012, REQ-QUIC-RFC9000-S10P3-0016, REQ-QUIC-RFC9000-S10P3-0028, REQ-QUIC-RFC9000-S10P3P1-0001, REQ-QUIC-RFC9000-S10P3P1-0008, REQ-QUIC-RFC9000-S10P3P1-0009, REQ-QUIC-RFC9000-S10P3P1-0011, REQ-QUIC-RFC9000-S10P3P1-0012, REQ-QUIC-RFC9000-S10P3P3-0001, REQ-QUIC-RFC9000-S10P3P3-0002, REQ-QUIC-RFC9000-S13P2P1-0014.
- Restructure-needed proof: 242 requirements. Examples: REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S13P2P3-0002, REQ-QUIC-RFC9000-S13P2P3-0003, REQ-QUIC-RFC9000-S13P2P3-0004, REQ-QUIC-RFC9000-S13P2P3-0007, REQ-QUIC-RFC9000-S13P2P3-0008, REQ-QUIC-RFC9000-S13P2P3-0009, REQ-QUIC-RFC9000-S13P2P3-0010.
- New proof or implementation work: 1223 requirements. Examples: REQ-QUIC-RFC9000-S10P1P2-0001, REQ-QUIC-RFC9000-S10P3P2-0010, REQ-QUIC-RFC9000-S10P3P2-0012, REQ-QUIC-RFC9000-S11-0003, REQ-QUIC-RFC9000-S11-0004, REQ-QUIC-RFC9000-S11-0005, REQ-QUIC-RFC9000-S11P1-0001, REQ-QUIC-RFC9000-S11P1-0002, REQ-QUIC-RFC9000-S11P1-0003, REQ-QUIC-RFC9000-S11P1-0004, REQ-QUIC-RFC9000-S11P1-0005, REQ-QUIC-RFC9000-S11P1-0006.
- Blocked by recorded gap families: 225 requirements. Examples: REQ-QUIC-RFC9000-S10-0001, REQ-QUIC-RFC9000-S10-0002, REQ-QUIC-RFC9000-S10P2-0002, REQ-QUIC-RFC9000-S10P2-0003, REQ-QUIC-RFC9000-S10P2-0005, REQ-QUIC-RFC9000-S10P2-0006, REQ-QUIC-RFC9000-S10P2-0007, REQ-QUIC-RFC9000-S10P2-0008, REQ-QUIC-RFC9000-S10P2-0009, REQ-QUIC-RFC9000-S10P2-0011, REQ-QUIC-RFC9000-S10P2-0012, REQ-QUIC-RFC9000-S10P2P1-0001.

## RFC Breakdown

| RFC | Total | trace_clean | missing_xrefs | proof_too_broad | partially_covered | uncovered_blocked | uncovered_unblocked |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 | 0 | 0 |
| RFC9000 | 1443 | 185 | 103 | 179 | 183 | 189 | 604 |
| RFC9001 | 61 | 6 | 15 | 0 | 14 | 26 | 0 |
| RFC9002 | 224 | 169 | 13 | 1 | 29 | 10 | 2 |
