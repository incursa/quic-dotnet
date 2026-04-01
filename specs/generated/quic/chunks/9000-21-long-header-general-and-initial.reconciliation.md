# RFC 9000 Chunk Reconciliation: `9000-21-long-header-general-and-initial`

## Scope

Source: `specs/requirements/quic/SPEC-QUIC-RFC9000.json`
RFC: `9000`
Section tokens: `S17`, `S17P1`, `S17P2`

## Status Summary

- implemented and tested: 17
- partially implemented: 8
- tested but implementation mapping unclear: 1
- not implemented: 11
- unclear / needs human review: 1

## Requirements in Scope

### S17

- `REQ-QUIC-RFC9000-S17-0001` - implemented and tested; numeric fields are read and written in network byte order.

### S17P1

- `REQ-QUIC-RFC9000-S17P1-0001` - not implemented; no packet-number encoding surface exists.
- `REQ-QUIC-RFC9000-S17P1-0002` - not implemented; no packet-number-space acknowledgement state exists.
- `REQ-QUIC-RFC9000-S17P1-0003` - not implemented; no sender-side packet-number sizing policy exists.
- `REQ-QUIC-RFC9000-S17P1-0004` - not implemented; no packet-number recovery heuristic exists.

### S17P2

- `REQ-QUIC-RFC9000-S17P2-0001` - implemented and tested; header-form classification rejects short-header-form inputs.
- `REQ-QUIC-RFC9000-S17P2-0002` - partially implemented; the fixed bit is preserved in `HeaderControlBits`, but it is not validated or rejected when zero.
- `REQ-QUIC-RFC9000-S17P2-0003` - partially implemented; the long-packet-type bits are preserved, but they are not surfaced as a dedicated field.
- `REQ-QUIC-RFC9000-S17P2-0004` - partially implemented; type-specific control bits are preserved only as part of the raw first-byte control bits.
- `REQ-QUIC-RFC9000-S17P2-0005` - implemented and tested; the version field is read and written as a 32-bit big-endian value.
- `REQ-QUIC-RFC9000-S17P2-0006` - implemented and tested; the destination CID length byte is read directly from the wire.
- `REQ-QUIC-RFC9000-S17P2-0007` - implemented and tested; version 1 is capped at 20 bytes and non-v1 long headers still exercise longer CID reads.
- `REQ-QUIC-RFC9000-S17P2-0008` - implemented and tested; the source CID length byte is read directly from the wire.
- `REQ-QUIC-RFC9000-S17P2-0009` - implemented and tested; source CID slicing follows the encoded length and the parser accepts the non-v1 long-CID test.
- `REQ-QUIC-RFC9000-S17P2-0010` - not implemented; there is no sender-path logic for pre-1-RTT packet selection.
- `REQ-QUIC-RFC9000-S17P2-0011` - not implemented; there is no sender-path logic for switching to short headers after 1-RTT keys.
- `REQ-QUIC-RFC9000-S17P2-0012` - implemented and tested; the long-header envelope is parsed and the control bits are preserved.
- `REQ-QUIC-RFC9000-S17P2-0013` - implemented and tested; the first-byte high bit is used to classify long headers.
- `REQ-QUIC-RFC9000-S17P2-0014` - partially implemented; the fixed bit is preserved, but ordinary long-header rejection for a zero fixed bit is not implemented.
- `REQ-QUIC-RFC9000-S17P2-0015` - partially implemented; zero-fixed-bit packets are not discarded by the parser.
- `REQ-QUIC-RFC9000-S17P2-0016` - partially implemented; packet-type bits are not parsed into a dedicated field.
- `REQ-QUIC-RFC9000-S17P2-0017` - implemented and tested; version zero maps to the Version Negotiation parse state.
- `REQ-QUIC-RFC9000-S17P2-0018` - implemented and tested; the destination CID length byte is followed by the encoded destination CID field.
- `REQ-QUIC-RFC9000-S17P2-0019` - implemented and tested; the length is carried as an 8-bit value.
- `REQ-QUIC-RFC9000-S17P2-0020` - implemented and tested; version 1 long headers with a destination CID up to 20 bytes are accepted.
- `REQ-QUIC-RFC9000-S17P2-0021` - implemented and tested; version 1 long headers with a destination CID longer than 20 bytes are rejected.
- `REQ-QUIC-RFC9000-S17P2-0022` - tested but implementation mapping unclear; the parser can read longer non-v1 CIDs, but there is no server-side Version Negotiation formation path in this repo.
- `REQ-QUIC-RFC9000-S17P2-0023` - implemented and tested; the destination CID field is sliced using the encoded length.
- `REQ-QUIC-RFC9000-S17P2-0024` - implemented and tested; the source CID length byte is read after the destination CID field.
- `REQ-QUIC-RFC9000-S17P2-0025` - implemented and tested; the source CID field is sliced using the encoded length.
- `REQ-QUIC-RFC9000-S17P2-0026` - partially implemented; trailing version-specific bytes are preserved, but the later packet-type-specific long-header fields are not parsed in this chunk.
- `REQ-QUIC-RFC9000-S17P2-0027` - partially implemented; the reserved bits are carried in `HeaderControlBits`, but there is no enforcement or pre-protection normalization.
- `REQ-QUIC-RFC9000-S17P2-0028` - not implemented; there is no encoder or protection stage that zeroes the pre-protection value.
- `REQ-QUIC-RFC9000-S17P2-0029` - not implemented; there is no post-protection protocol-error path.
- `REQ-QUIC-RFC9000-S17P2-0030` - unclear / needs human review; this security note has no direct code artifact in the current repo.
- `REQ-QUIC-RFC9000-S17P2-0031` - not implemented; packet-number field parsing and encoding do not exist in this repo.
- `REQ-QUIC-RFC9000-S17P2-0032` - not implemented; packet-number length handling is absent.
- `REQ-QUIC-RFC9000-S17P2-0033` - not implemented; packet-number length bits are not modeled.

## Generated Inputs Consulted

- `specs/generated/quic/import-audit-summary.md`
- `specs/generated/quic/import-audit-details.json`
- `specs/generated/quic/import-missing-coverage.md`
- `specs/generated/quic/implementation-chunk-manifest.md`
- `specs/generated/quic/quic-existing-work-inventory.md`
- `specs/generated/quic/9000.assembly-map.json`

## Existing Implementation Evidence

- `src/Incursa.Quic/QuicPacketParser.cs:11-93` classifies headers and parses long, short, and Version Negotiation packet views.
- `src/Incursa.Quic/QuicPacketParsing.cs:23-52` reads the long-header envelope, including the new version-1 destination CID cap.
- `src/Incursa.Quic/QuicLongHeaderPacket.cs:31-71` exposes the long-header fields and trailing version-specific bytes.
- `src/Incursa.Quic/QuicVersionNegotiationPacket.cs:30-87` exposes the Version Negotiation header view and supported-version list.
- `src/Incursa.Quic/QuicShortHeaderPacket.cs:20-30` exposes the short-header remainder view.
- `tests/Incursa.Quic.Tests/QuicHeaderTestData.cs:15-52` builds long headers and Version Negotiation packets in big-endian wire order.
- `benchmarks/QuicHeaderParsingBenchmarks.cs:83-135` benchmarks short-header classification, long-header parsing, Version Negotiation parsing, and short-header parsing.
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs:31-72` intentionally generates arbitrary 7-bit control values for the property and fuzz tests.

## Existing Test Evidence

- `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs:11-50` covers header-form classification, empty-input rejection, and control-bit preservation.
- `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs:5-170` covers long-header round-trips, truncation rejection, zero-version state, short-header rejection, missing length-byte rejection, the new max-length CID case, and the new version-1 CID boundary checks.
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs:7-102` covers the long-header envelope, control-bit preservation, short-header opaque remainder, and Version Negotiation round-trips.
- `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs:5-97` fuzzes long-header and Version Negotiation parsing, including truncation rejection.
- `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs:5-144` exercises supported-version exposure and negative VN cases.
- `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs:5-42` exercises short-header parsing and rejection.
- `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs:23-103` provides the packet generators used by the property tests.
- The live test convention is xUnit `Trait("Requirement", "...")`, and the in-scope long-header traits now use the canonical RFC 9000 IDs.

## Old -> New Requirement ID Mappings Applied

- Legacy header ID 0001 was retagged to the imported RFC 9000 header-form ID set, including `REQ-QUIC-RFC9000-S17P2-0013`.
- Legacy header ID 0002 was retagged to `REQ-QUIC-RFC9000-S17P2-0012`.
- Legacy header IDs 0003 through 0006 were split across the atomic RFC 9000 long-header field IDs for version, CID lengths, CID payloads, and trailing data.
- Legacy header ID 0007 remains on the short-header chunk and was intentionally not rewritten here.
- Legacy header IDs 0008 through 0010 remain on the Version Negotiation-specific chunk and were intentionally not rewritten here.
- `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs` gained two new canonical RFC 9000 boundary tests for `REQ-QUIC-RFC9000-S17P2-0020` and `REQ-QUIC-RFC9000-S17P2-0021`.

## Gaps Fixed in This Pass

- Rewrote the in-scope xUnit requirement traits from the legacy header names to the imported RFC 9000 IDs.
- Added a parser check that rejects version 1 long headers whose destination CID length exceeds 20 bytes.
- Added explicit positive and negative boundary tests for that version 1 CID limit.
- Added an explicit long-CID round-trip test for a non-v1 long header to preserve the Version Negotiation read capability.
- Left the short-header and Version Negotiation legacy IDs in place because they belong to later chunks.

## Remaining Gaps

- Section 17.1 packet-number encoding and packet-number sizing are still absent.
- Requirements `REQ-QUIC-RFC9000-S17P2-0002` through `REQ-QUIC-RFC9000-S17P2-0004`, `REQ-QUIC-RFC9000-S17P2-0014` through `REQ-QUIC-RFC9000-S17P2-0016`, and `REQ-QUIC-RFC9000-S17P2-0026` through `REQ-QUIC-RFC9000-S17P2-0027` still preserve raw control bits rather than enforcing the underlying semantics.
- Requirements `REQ-QUIC-RFC9000-S17P2-0028` and `REQ-QUIC-RFC9000-S17P2-0029` remain unimplemented because there is no protection stage in the repo.
- `REQ-QUIC-RFC9000-S17P2-0022` remains capability-only and needs a server-side Version Negotiation formation path if we want direct proof.
- The repository still has no packet-protection stage, so the security guidance in `REQ-QUIC-RFC9000-S17P2-0030` has no direct proof artifact yet.
- The out-of-scope short-header and Version Negotiation legacy traits remain for the later RFC 9000 chunks.

## Requirements Needing Deeper Implementation Work

- `REQ-QUIC-RFC9000-S17P1-0001` through `REQ-QUIC-RFC9000-S17P1-0004`
- `REQ-QUIC-RFC9000-S17P2-0002` through `REQ-QUIC-RFC9000-S17P2-0004`
- `REQ-QUIC-RFC9000-S17P2-0014` through `REQ-QUIC-RFC9000-S17P2-0016`
- `REQ-QUIC-RFC9000-S17P2-0026` through `REQ-QUIC-RFC9000-S17P2-0029`
- `REQ-QUIC-RFC9000-S17P2-0031` through `REQ-QUIC-RFC9000-S17P2-0033`

## Tests Run and Results

- Command: `dotnet test tests/Incursa.Quic.Tests/Incursa.Quic.Tests.csproj --filter "FullyQualifiedName~QuicPacketParserTests|FullyQualifiedName~QuicLongHeaderPacketTests|FullyQualifiedName~QuicHeaderPropertyTests|FullyQualifiedName~QuicHeaderFuzzTests|FullyQualifiedName~QuicVersionNegotiationPacketTests|FullyQualifiedName~QuicShortHeaderPacketTests"`
- Passed: 37
- Failed: 0
- Skipped: 0
- Duration: 353 ms
