# RFC 8999 Chunk Reconciliation: `8999-01-invariants`

## Requirements in scope

Source: `specs/requirements/quic/SPEC-QUIC-RFC8999.json`

- `REQ-QUIC-RFC8999-S5P1-0001` Header Form Bit
- `REQ-QUIC-RFC8999-S5P1-0002` Version-Specific Bits
- `REQ-QUIC-RFC8999-S5P1-0003` Version Field
- `REQ-QUIC-RFC8999-S5P1-0004` Destination Connection ID Length Encoding
- `REQ-QUIC-RFC8999-S5P1-0005` Destination Connection ID Size
- `REQ-QUIC-RFC8999-S5P1-0006` Source Connection ID Length Encoding
- `REQ-QUIC-RFC8999-S5P1-0007` Source Connection ID Size
- `REQ-QUIC-RFC8999-S5P1-0008` Version-Specific Remainder

## Generated inputs consulted

- `specs/generated/quic/import-audit-summary.md`: RFC 8999 import status is `Pass`; missing ARC/WI/VER artifacts are still expected downstream.
- `specs/generated/quic/implementation-chunk-manifest.md`: `RFC8999-01` is already marked `impl yes` and `tests yes`.
- `specs/generated/quic/core-validation.json`: current `REQ-CLAUSE` namespace mismatches for `REQ-QUIC-RFC8999-S5P1-*` are validator-policy noise, not import defects.

## Existing implementation evidence

- `REQ-QUIC-RFC8999-S5P1-0001`
  - `src/Incursa.Quic/QuicPacketParser.cs:11` classifies the header form from the first-byte high bit.
  - `src/Incursa.Quic/QuicPacketParsing.cs:24` rejects long-header parsing when the first-byte high bit is clear.
- `REQ-QUIC-RFC8999-S5P1-0002`
  - `src/Incursa.Quic/QuicPacketParsing.cs:28` preserves the seven non-form bits as opaque `headerControlBits`.
  - `src/Incursa.Quic/QuicLongHeaderPacket.cs:36` and `src/Incursa.Quic/QuicVersionNegotiationPacket.cs:35` expose those bits without interpreting them.
- `REQ-QUIC-RFC8999-S5P1-0003`
  - `src/Incursa.Quic/QuicPacketParsing.cs:29` reads the 32-bit Version field.
  - `src/Incursa.Quic/QuicLongHeaderPacket.cs:41` and `src/Incursa.Quic/QuicVersionNegotiationPacket.cs:40` expose the parsed version state.
- `REQ-QUIC-RFC8999-S5P1-0004`
  - `src/Incursa.Quic/QuicPacketParsing.cs:31` reads the Destination Connection ID length byte from offset 5.
- `REQ-QUIC-RFC8999-S5P1-0005`
  - `src/Incursa.Quic/QuicPacketParsing.cs:45` slices the Destination Connection ID using the encoded length.
  - `src/Incursa.Quic/QuicLongHeaderPacket.cs:56` and `src/Incursa.Quic/QuicVersionNegotiationPacket.cs:55` expose the parsed size.
- `REQ-QUIC-RFC8999-S5P1-0006`
  - `src/Incursa.Quic/QuicPacketParsing.cs:33` and `src/Incursa.Quic/QuicPacketParsing.cs:39` read and validate the Source Connection ID length byte.
- `REQ-QUIC-RFC8999-S5P1-0007`
  - `src/Incursa.Quic/QuicPacketParsing.cs:46` slices the Source Connection ID using the encoded length.
  - `src/Incursa.Quic/QuicLongHeaderPacket.cs:66` and `src/Incursa.Quic/QuicVersionNegotiationPacket.cs:65` expose the parsed size.
- `REQ-QUIC-RFC8999-S5P1-0008`
  - `src/Incursa.Quic/QuicPacketParsing.cs:47` preserves the trailing version-specific remainder.
  - `src/Incursa.Quic/QuicLongHeaderPacket.cs:71` and `src/Incursa.Quic/QuicVersionNegotiationPacket.cs:70` expose the remainder.
- Benchmark evidence
  - `benchmarks/QuicHeaderParsingBenchmarks.cs:98`
  - `benchmarks/QuicHeaderParsingBenchmarks.cs:109`
  - `benchmarks/QuicHeaderParsingBenchmarks.cs:120`

## Existing test evidence

- `REQ-QUIC-RFC8999-S5P1-0001`
  - `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs:24`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:10`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:83`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:93`
- `REQ-QUIC-RFC8999-S5P1-0002`
  - `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs:39`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`
- `REQ-QUIC-RFC8999-S5P1-0003`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:56`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:64`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`
- `REQ-QUIC-RFC8999-S5P1-0004`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:56`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:115`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`
- `REQ-QUIC-RFC8999-S5P1-0005`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:56`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:115`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`
- `REQ-QUIC-RFC8999-S5P1-0006`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:56`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:95`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:115`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`
- `REQ-QUIC-RFC8999-S5P1-0007`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:56`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:115`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`
- `REQ-QUIC-RFC8999-S5P1-0008`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:14`
  - `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:115`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:30`
  - `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:71`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:15`
  - `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:57`
  - `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:15`

## Old -> new requirement ID mappings applied

- Legacy header ID 0001 -> `REQ-QUIC-RFC8999-S5P1-0001` for the in-scope classification tests.
- Legacy header ID 0002 -> `REQ-QUIC-RFC8999-S5P1-0002` for preserved long-header control-bit coverage.
- Legacy header IDs 0003 through 0006 were rewritten test-by-test to `REQ-QUIC-RFC8999-S5P1-0003` through `REQ-QUIC-RFC8999-S5P1-0007` where the assertions directly cover the imported RFC 8999 invariants.
- Legacy header IDs 0008 through 0010 were rewritten to the matching `REQ-QUIC-RFC8999-S5P1-*` IDs only in mixed long-header/Version Negotiation tests that still prove the shared RFC 8999 invariant surface.

## Gaps fixed in this pass

- Rewrote in-scope xUnit `Trait("Requirement", "...")` tags from legacy header identifiers to canonical `REQ-QUIC-RFC8999-S5P1-*` identifiers.
- Added `TryParseLongHeader_AcceptsMaximumLengthConnectionIds` to cover the 255-byte upper bound for both connection IDs and preserve the trailing version-specific remainder.
- Left short-header-only and Version Negotiation-specific legacy requirement tags untouched when they belong to later RFC 9000 reconciliation work rather than RFC 8999 Section 5.1.

## Remaining gaps

- The documented `specs/requirements/quic/REQUIREMENT-GAPS.md` path is not present in the repository, so there is no chunk-local gap ledger to update for this pass.
- Short-header tests still carry the legacy header ID 0007 tag and must be reconciled with the later RFC 9000 short-header chunk, not with `8999-01-invariants`.
- Several Version Negotiation-specific negative tests still carry legacy header IDs 0010 and 0008 because they verify later RFC 9000 semantics rather than the RFC 8999 shared long-header invariant set.
- The import summary still notes that no ARC, WI, or VER artifacts were created by the import run; this pass did not author those canonical proof artifacts.

## Requirements needing deeper implementation work

- None within `REQ-QUIC-RFC8999-S5P1-0001` through `REQ-QUIC-RFC8999-S5P1-0008`. The current parser/view implementation and the updated tests cover the selected chunk.
- Follow-on work is traceability-oriented, not implementation-oriented: reconcile the remaining legacy short-header and Version Negotiation requirement IDs in the later RFC 9000 chunks and add canonical ARC/WI/VER artifacts when the workflow requires them.

## Per-requirement status

| Requirement | Status | Notes |
| --- | --- | --- |
| `REQ-QUIC-RFC8999-S5P1-0001` | implemented and tested | Header-form classification and long-header rejection are covered. |
| `REQ-QUIC-RFC8999-S5P1-0002` | implemented and tested | The parser preserves the seven opaque long-header bits. |
| `REQ-QUIC-RFC8999-S5P1-0003` | implemented and tested | The parser reads and exposes the 32-bit Version field, including `0`. |
| `REQ-QUIC-RFC8999-S5P1-0004` | implemented and tested | The parser consumes the Destination Connection ID length byte directly from the wire. |
| `REQ-QUIC-RFC8999-S5P1-0005` | implemented and tested | Added explicit 255-byte coverage for the Destination Connection ID upper bound. |
| `REQ-QUIC-RFC8999-S5P1-0006` | implemented and tested | Source Connection ID length-byte parsing and truncation rejection are covered. |
| `REQ-QUIC-RFC8999-S5P1-0007` | implemented and tested | Added explicit 255-byte coverage for the Source Connection ID upper bound. |
| `REQ-QUIC-RFC8999-S5P1-0008` | implemented and tested | The parser preserves the version-specific remainder as opaque trailing data. |

## Tests run and results

Command:

```text
dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests"
```

Result:

- Passed: 32
- Failed: 0
- Skipped: 0
- Duration: 154 ms
