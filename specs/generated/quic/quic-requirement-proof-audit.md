# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 2052 |
| full_executable_proof | 625 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 451 | 0 | 999 | 0 |
| RFC9001 | 96 | 68 | 0 | 28 | 0 |
| RFC9002 | 226 | 41 | 0 | 185 | 0 |
| RFC9114 | 8 | 0 | 0 | 8 | 0 |
| RFC9204 | 3 | 0 | 0 | 3 | 0 |
| RFC9220 | 31 | 8 | 0 | 23 | 0 |
| RFC9221 | 33 | 33 | 0 | 0 | 0 |
| RFC9250 | 141 | 1 | 0 | 140 | 0 |
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
| `REQ-QUIC-RFC9000-0019` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0020` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0021` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0022` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0023` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0024` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0025` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0027` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0028` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0031` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0032` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0033` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0034` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0045` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0047` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0048` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0057` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0082` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0083` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0097` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0098` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0110` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0113` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0115` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0120` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0157` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0158` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0159` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0162` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0163` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0164` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0167` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0168` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0170` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0173` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0176` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0177` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0180` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0185` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0186` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0194` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0215` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0219` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0220` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0221` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0222` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0240` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0244` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0245` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0247` | RFC9000 | deferred_proof_not_executed |  | fuzz |
