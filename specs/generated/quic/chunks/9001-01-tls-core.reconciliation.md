# RFC 9001 Chunk Reconciliation: `9001-01-tls-core`

## Requirements in scope

Source: `specs/requirements/quic/SPEC-QUIC-RFC9001.json`

### S2
- `REQ-QUIC-RFC9001-S2-0001` Interpret uppercase BCP 14 keywords - `unclear / needs human review`

### S3
- `REQ-QUIC-RFC9001-S3-0001` Assume packet confidentiality - `not implemented`
- `REQ-QUIC-RFC9001-S3-0002` Derive packet keys from TLS handshake - `not implemented`
- `REQ-QUIC-RFC9001-S3-0003` Carry handshake and alert messages directly - `not implemented`
- `REQ-QUIC-RFC9001-S3-0004` Replace the TLS record layer - `not implemented`
- `REQ-QUIC-RFC9001-S3-0005` Rely on TLS for security-critical functions - `not implemented`
- `REQ-QUIC-RFC9001-S3-0006` Use the TLS handshake - `not implemented`
- `REQ-QUIC-RFC9001-S3-0007` Use QUIC-provided delivery services - `not implemented`
- `REQ-QUIC-RFC9001-S3-0008` Send TLS messages via QUIC - `not implemented`
- `REQ-QUIC-RFC9001-S3-0009` Provide a reliable stream abstraction - `not implemented`
- `REQ-QUIC-RFC9001-S3-0010` Provide TLS updates to QUIC - `not implemented`
- `REQ-QUIC-RFC9001-S3-0011` Do not use TLS Application Data records - `not implemented`
- `REQ-QUIC-RFC9001-S3-0012` Send data as QUIC frames - `not implemented`

### S4
- `REQ-QUIC-RFC9001-S4-0001` Carry handshake data in CRYPTO frames - `not implemented`
- `REQ-QUIC-RFC9001-S4-0002` Define CRYPTO frame boundaries - `not implemented`
- `REQ-QUIC-RFC9001-S4-0003` Package and encrypt CRYPTO frames - `not implemented`
- `REQ-QUIC-RFC9001-S4-0004` Package and encrypt CRYPTO frames - `not implemented`
- `REQ-QUIC-RFC9001-S4-0005` Deliver handshake data reliably - `not implemented`
- `REQ-QUIC-RFC9001-S4-0006` Associate TLS-produced chunks with current keys - `not implemented`
- `REQ-QUIC-RFC9001-S4-0007` Retransmit with the same keys - `not implemented`
- `REQ-QUIC-RFC9001-S4-0008` Map encryption levels to packet number spaces - `not implemented`
- `REQ-QUIC-RFC9001-S4-0009` Let packet number space determine frame semantics - `not implemented`
- `REQ-QUIC-RFC9001-S4-0010` Indicate packet keys via packet type - `not implemented`
- `REQ-QUIC-RFC9001-S4-0011` Prefer coalesced packets - `not implemented`

### S5
- `REQ-QUIC-RFC9001-S5-0001` Protect packets with TLS-derived keys - `partially implemented`
- `REQ-QUIC-RFC9001-S5-0002` Use the TLS-negotiated AEAD - `partially implemented`
- `REQ-QUIC-RFC9001-S5-0003` Leave Version Negotiation packets unprotected - `not implemented`
- `REQ-QUIC-RFC9001-S5-0004` Protect Retry packets with AEAD_AES_128_GCM - `not implemented`
- `REQ-QUIC-RFC9001-S5-0005` Use AEAD_AES_128_GCM for Initial packets - `not implemented`
- `REQ-QUIC-RFC9001-S5-0006` Derive Initial keys from the first client Initial - `not implemented`
- `REQ-QUIC-RFC9001-S5-0007` Protect all other packets cryptographically - `not implemented`
- `REQ-QUIC-RFC9001-S5-0008` Apply the same protection process to Initial packets - `not implemented`
- `REQ-QUIC-RFC9001-S5-0009` Treat Initial packets as lacking confidentiality and integrity protection - `not implemented`
- `REQ-QUIC-RFC9001-S5-0010` Use a fixed key for Retry packets - `not implemented`

### S6
- `REQ-QUIC-RFC9001-S6-0001` Allow key update after handshake confirmation - `not implemented`
- `REQ-QUIC-RFC9001-S6-0002` Identify packet protection keys with Key Phase - `not implemented`
- `REQ-QUIC-RFC9001-S6-0003` Initialize Key Phase to zero - `not implemented`
- `REQ-QUIC-RFC9001-S6-0004` Toggle Key Phase on each update - `not implemented`
- `REQ-QUIC-RFC9001-S6-0005` Let Key Phase detect key changes - `not implemented`
- `REQ-QUIC-RFC9001-S6-0006` Update keys when Key Phase changes - `not implemented`
- `REQ-QUIC-RFC9001-S6-0007` Decrypt the packet with the changed Key Phase - `not implemented`
- `REQ-QUIC-RFC9001-S6-0008` Update both endpoints on key update - `not implemented`
- `REQ-QUIC-RFC9001-S6-0009` Prohibit TLS KeyUpdate messages - `not implemented`
- `REQ-QUIC-RFC9001-S6-0010` Treat TLS KeyUpdate as a connection error - `not implemented`

## Status summary

| Status | Count |
| --- | ---: |
| unclear / needs human review | 1 |
| not implemented | 41 |
| partially implemented | 2 |

## Generated inputs consulted

- `specs/generated/quic/import-audit-summary.md`: RFC 9001 import status is `Pass`; no import defects remain.
- `specs/generated/quic/import-missing-coverage.md`: step-2 coverage is clean for RFC 9001; no audit-relevant mismatch remains.
- `specs/generated/quic/implementation-chunk-manifest.md`: `RFC9001-01` and `RFC9001-02` are both marked `impl no` / `tests no`.
- `specs/generated/quic/9001.assembly-map.json`: canonical final IDs and historical draft-id provenance are already recorded.
- `specs/generated/quic/import-audit-details.json`: RFC 9001 repair is complete; only validator-policy mismatch remains downstream.

## Existing implementation evidence

- Direct implementation refs now exist for the narrow non-Initial packet-protection material boundary:
  `src/Incursa.Quic/QuicAeadAlgorithm.cs`, `src/Incursa.Quic/QuicAeadUsageLimitCalculator.cs`, `src/Incursa.Quic/QuicTlsPacketProtectionMaterial.cs`, `src/Incursa.Quic/QuicTlsTransport.cs`, and `src/Incursa.Quic/QuicTransportTlsBridgeState.cs`.
- The closest live packet-framing code is still the packet-header parser surface (`src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`), but it still does not implement RFC 9001 handshake packet I/O or packet protect/open helpers.

## Existing test evidence

- Direct RFC 9001 requirement-home tests now cover `REQ-QUIC-RFC9001-S5-0001` and `REQ-QUIC-RFC9001-S5-0002` under `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001`.
- The broader packet-header tests (`tests/Incursa.Quic.Tests/QuicPacketParserTests.cs`, `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`) still target RFC 8999 / RFC 9000 behavior and do not imply handshake support.

## Old -> new requirement ID mappings applied

- No live code or test references were rewritten in this pass.
- Historical draft IDs in `specs/generated/rfc9001/1-6.review.md` and `specs/generated/rfc9001/1-6.requirements.draft.md` already map to the canonical `REQ-QUIC-RFC9001-*` IDs through `specs/generated/quic/9001.assembly-map.json`; those provenance files were left untouched.

## Gaps fixed in this pass

- `REQ-QUIC-RFC9001-S5-0001`: introduced a narrow non-Initial packet-protection material model with explicit encryption-level typing and malformed-input rejection.
- `REQ-QUIC-RFC9001-S5-0002`: threaded negotiated AEAD-bound material through the TLS bridge/runtime seam and made the binding explicit instead of Initial-only.

## Remaining gaps

- `S2`: `REQ-QUIC-RFC9001-S2-0001` remains `unclear / needs human review`.
- `S3`: `REQ-QUIC-RFC9001-S3-0001` through `REQ-QUIC-RFC9001-S3-0012` remain `not implemented`.
- `S4`: `REQ-QUIC-RFC9001-S4-0001` through `REQ-QUIC-RFC9001-S4-0011` remain `not implemented`.
- `S5`: `REQ-QUIC-RFC9001-S5-0001` and `REQ-QUIC-RFC9001-S5-0002` are now partially implemented; `REQ-QUIC-RFC9001-S5-0004` through `REQ-QUIC-RFC9001-S5-0010` remain `not implemented`.
- `S6`: `REQ-QUIC-RFC9001-S6-0001` through `REQ-QUIC-RFC9001-S6-0010` remain `not implemented`.
- The current repository now has the non-Initial packet-protection material boundary, but it still does not contain RFC 9001 handshake packet I/O or key-update implementation surfaces, so the Handshake half of `S5-0007` remains blocked.

## Requirements needing deeper implementation work

- `S2`: `REQ-QUIC-RFC9001-S2-0001` is a document-level rule and needs human review to determine whether a repo artifact should capture it.
- `S3`: `REQ-QUIC-RFC9001-S3-0001` through `REQ-QUIC-RFC9001-S3-0012` need TLS/QUIC integration implementation and proof.
- `S4`: `REQ-QUIC-RFC9001-S4-0001` through `REQ-QUIC-RFC9001-S4-0011` need CRYPTO-frame, packet-number-space, and encryption-level implementation work.
- `S5`: `REQ-QUIC-RFC9001-S5-0004` through `REQ-QUIC-RFC9001-S5-0010` still need packet-protection, secret-derivation, Retry, and Version Negotiation protection work; the Handshake half of `REQ-QUIC-RFC9001-S5-0007` still needs packet I/O plumbing.
- `S6`: `REQ-QUIC-RFC9001-S6-0001` through `REQ-QUIC-RFC9001-S6-0010` need key-update and AEAD-limit implementation work.

## Files written

- `specs/generated/quic/chunks/9001-01-tls-core.reconciliation.md`
- `specs/generated/quic/chunks/9001-01-tls-core.reconciliation.json`

## Tests run and results

```text
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj
```

- Passed: 1461
- Failed: 0
- Skipped: 0
- Duration: not recorded in this pass
