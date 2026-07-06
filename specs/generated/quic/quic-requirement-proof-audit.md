# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 1550 |
| full_executable_proof | 1127 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 953 | 0 | 497 | 0 |
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
| `REQ-QUIC-RFC9000-0028` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0057` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0278` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0316` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0317` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0332` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0412` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0447` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0460` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0467` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0468` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0475` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0476` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0488` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0495` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0498` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0510` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0518` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0519` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0520` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0525` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0529` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0531` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0541` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0542` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0545` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0548` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0658` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0659` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0665` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0682` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0804` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0831` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0851` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0856` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0857` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0905` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0906` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0913` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0914` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0915` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0916` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0939` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0944` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0969` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0972` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0976` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0980` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0985` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0986` | RFC9000 | deferred_proof_not_executed |  | fuzz |
