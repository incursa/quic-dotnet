# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 67 |
| full_executable_proof | 2610 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 1450 | 0 | 0 | 0 |
| RFC9001 | 96 | 96 | 0 | 0 | 0 |
| RFC9002 | 226 | 226 | 0 | 0 | 0 |
| RFC9114 | 8 | 8 | 0 | 0 | 0 |
| RFC9204 | 3 | 3 | 0 | 0 | 0 |
| RFC9220 | 31 | 31 | 0 | 0 | 0 |
| RFC9221 | 33 | 33 | 0 | 0 | 0 |
| RFC9250 | 141 | 141 | 0 | 0 | 0 |
| RFC9287 | 4 | 4 | 0 | 0 | 0 |
| RFC9297 | 84 | 84 | 0 | 0 | 0 |
| RFC9298 | 116 | 116 | 0 | 0 | 0 |
| RFC9308 | 10 | 10 | 0 | 0 | 0 |
| RFC9312 | 5 | 5 | 0 | 0 | 0 |
| RFC9368 | 7 | 7 | 0 | 0 | 0 |
| RFC9369 | 3 | 3 | 0 | 0 | 0 |
| RFC9461 | 42 | 1 | 0 | 41 | 0 |
| RFC9463 | 120 | 120 | 0 | 0 | 0 |
| RFC9464 | 77 | 51 | 0 | 26 | 0 |
| RFC9484 | 213 | 213 | 0 | 0 | 0 |

## First Non-Full-Proof Items

| Requirement | RFC | Proof state | Missing required | Deferred missing |
| --- | --- | --- | --- | --- |
| `REQ-QUIC-RFC9461-0001` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0002` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0003` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0004` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0005` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0006` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0007` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0008` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0009` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0010` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0020` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0021` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0028` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0029` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0030` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0031` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0032` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0033` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0034` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0035` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0036` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0037` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0038` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0040` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0041` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9461-0042` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P1-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P1-S1-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P1-S2-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P1-S2-R02` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P2-S1-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P2-S2-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P3-S1-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P3-S2-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S5-P3-S3-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S8-1-2-P3-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S8-1-2-P3-S1-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S8-1-2-P3-S1-R02` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S8-1-P2-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S8-2-P2-S3-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `RFC9461-S8-2-P2-S4-R01` | RFC9461 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0050` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0051` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0052` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0053` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0054` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0055` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0056` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0060` | RFC9464 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9464-0062` | RFC9464 | deferred_proof_not_executed |  | fuzz |
