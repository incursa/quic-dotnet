# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 337 |
| full_executable_proof | 2340 |

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
| RFC9297 | 84 | 0 | 0 | 84 | 0 |
| RFC9298 | 116 | 0 | 0 | 116 | 0 |
| RFC9308 | 10 | 10 | 0 | 0 | 0 |
| RFC9312 | 5 | 5 | 0 | 0 | 0 |
| RFC9368 | 7 | 7 | 0 | 0 | 0 |
| RFC9369 | 3 | 3 | 0 | 0 | 0 |
| RFC9461 | 42 | 1 | 0 | 41 | 0 |
| RFC9463 | 120 | 101 | 0 | 19 | 0 |
| RFC9464 | 77 | 0 | 0 | 77 | 0 |
| RFC9484 | 213 | 213 | 0 | 0 | 0 |

## First Non-Full-Proof Items

| Requirement | RFC | Proof state | Missing required | Deferred missing |
| --- | --- | --- | --- | --- |
| `REQ-QUIC-RFC9297-0001` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0002` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0003` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0008` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0009` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0010` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0011` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0013` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0014` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0015` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0016` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0017` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0026` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0027` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0028` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0029` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0031` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0032` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0033` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0034` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0036` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0037` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0038` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0039` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0040` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0041` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0042` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0043` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0044` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0045` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0046` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0052` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0053` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0056` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0057` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0061` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0062` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0063` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0064` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0066` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0067` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0070` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0072` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0073` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0074` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0075` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0076` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0077` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0078` | RFC9297 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9297-0079` | RFC9297 | deferred_proof_not_executed |  | fuzz |
