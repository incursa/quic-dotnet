# QUIC Requirement Proof Audit

This report is stricter than trace coverage. It only counts focused executable method-level evidence toward required proof dimensions.

## Summary

| Proof state | Count |
| --- | ---: |
| deferred_proof_not_executed | 1428 |
| full_executable_proof | 1249 |

## RFC Breakdown

| RFC | Total | full_executable_proof | missing_required_focused_proof | deferred_proof_not_executed | no_focused_executable_proof |
| --- | ---: | ---: | ---: | ---: | ---: |
| RFC8999 | 8 | 8 | 0 | 0 | 0 |
| RFC9000 | 1450 | 1067 | 0 | 383 | 0 |
| RFC9001 | 96 | 68 | 0 | 28 | 0 |
| RFC9002 | 226 | 41 | 0 | 185 | 0 |
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
| `REQ-QUIC-RFC9000-0028` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0057` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0682` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0831` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0856` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-0857` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1009` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1011` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1015` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1018` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1259` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1291` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1292` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1293` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1322` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-13230` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-13234` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1328` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1330` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1340` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1344` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1366` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1371` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1372` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1373` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1376` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1377` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1378` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1383` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1488` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1514` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-1735` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-19150001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-19150002` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-19150004` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-19150006` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-19150007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-19150008` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P1-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P1-0003` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P1P1-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P1P2-0002` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P2-0007` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P2-0008` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P2P2-0005` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S10P3P3-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S11P1-0005` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S11P2-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S11P2-0004` | RFC9000 | deferred_proof_not_executed |  | fuzz |
| `REQ-QUIC-RFC9000-S13-0001` | RFC9000 | deferred_proof_not_executed |  | fuzz |
