# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 1298 |
| full_executable_proof | 1379 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 1188 | 0 | 262 | 0 |
| RFC9001 | 96 | 69 | 0 | 27 | 0 |
| RFC9002 | 226 | 49 | 0 | 177 | 0 |
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
| `REQ-QUIC-RFC9000-0857` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1376` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1377` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1378` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1383` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P2-0007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P2-0008` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S11P1-0005` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S17P2P5P1-0006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S17P2P5P3-0007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S21P10-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S3-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S3-0003` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5-0005` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5-0006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P2P1-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P2P3-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P2P3-0002` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P3-0008` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S5P3-0010` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7-0006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7-0007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7P3-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7P4P1-0010` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7P4P1-0012` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S7P5-0004` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S8P1P3-0012` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S8P1P4-0010` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S9P3P2-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S9P3P2-0004` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-1-2-P3-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P2-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P3-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P4-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P4-S3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P5-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P5-S3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-1-P7-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-2-P3-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-3-P3-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-P5-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-P6-S3-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-P7-S1-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-2-P7-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-3-1-P2-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-3-1-P2-S2-R02` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-3-1-P4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-3-2-P4-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-3-2-P5-S2-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `RFC9000-S10-3-2-P5-S4-R01` | RFC9000 | deferred_proof_not_executed |  | fuzz |
