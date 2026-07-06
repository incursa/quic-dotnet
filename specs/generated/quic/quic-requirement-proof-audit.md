# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 1113 |
| full_executable_proof | 1564 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 1362 | 0 | 88 | 0 |
| RFC9001 | 96 | 72 | 0 | 24 | 0 |
| RFC9002 | 226 | 57 | 0 | 169 | 0 |
| RFC9114 | 8 | 0 | 0 | 8 | 0 |
| RFC9204 | 3 | 0 | 0 | 3 | 0 |
| RFC9220 | 31 | 8 | 0 | 23 | 0 |
| RFC9221 | 33 | 33 | 0 | 0 | 0 |
| RFC9250 | 141 | 9 | 0 | 132 | 0 |
| RFC9287 | 4 | 4 | 0 | 0 | 0 |
| RFC9297 | 84 | 0 | 0 | 84 | 0 |
| RFC9298 | 116 | 0 | 0 | 116 | 0 |
| RFC9308 | 10 | 0 | 0 | 10 | 0 |
| RFC9312 | 5 | 0 | 0 | 5 | 0 |
| RFC9368 | 7 | 7 | 0 | 0 | 0 |
| RFC9369 | 3 | 3 | 0 | 0 | 0 |
| RFC9461 | 42 | 1 | 0 | 41 | 0 |
| RFC9463 | 120 | 0 | 0 | 120 | 0 |
| RFC9464 | 77 | 0 | 0 | 77 | 0 |
| RFC9484 | 213 | 0 | 0 | 213 | 0 |

## First Non-Full-Proof Items

| Requirement | RFC | Proof state | Missing required | Deferred missing |
| --- | --- | --- | --- | --- |
| `REQ-QUIC-RFC9000-S17P2P5P3-0007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5-0005` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5-0006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P2P3-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P3-0010` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7-0006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7-0007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S12-2-P5-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S17-2-5-3-P4-S6-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S19-13-P1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S19-21-P3-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S19-21-P4-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S19-21-P4-S1-R02` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-11-P2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-11-P3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-3-P2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-5-6-P2-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-5-6-P2-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-5-6-P3-S3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-5-6-P5-S4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-5-P8-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-6-P2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S21-7-P4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-2-P1-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-2-P4-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-3-P2-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-3-P2-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-3-P3-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-3-P4-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S22-1-4-P4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S3-2-P6-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S4-5-P4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S4-6-P2-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S4-6-P2-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-1-1-P5-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-1-1-P8-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-1-2-P5-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-1-2-P7-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-1-P4-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-1-P9-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-1-P3-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-2-P1-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-2-P1-S3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-2-P2-S4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-2-P5-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-2-P6-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-2-P7-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S5-2-P6-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S6-1-P3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S6-3-P2-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
