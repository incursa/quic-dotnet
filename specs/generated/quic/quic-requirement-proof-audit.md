# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 1514 |
| full_executable_proof | 1163 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 989 | 0 | 461 | 0 |
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
| `REQ-QUIC-RFC9000-0467` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0468` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0682` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0831` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0856` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0857` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0969` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0972` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0976` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0980` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0985` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0986` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1009` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1011` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1015` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1018` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1033` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1034` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1059` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1071` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1073` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1075` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1100` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1145` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1146` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1147` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1151` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1154` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1156` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1157` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1158` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1162` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1177` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1179` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1192` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1198` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1203` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1205` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1220006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1220010` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1222` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1237` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1243` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1245` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1259` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1273` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1282` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1283` | RFC9000 | deferred_proof_not_executed |  | fuzz |
