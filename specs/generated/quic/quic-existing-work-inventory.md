# QUIC Existing Work Inventory

## Executive Summary

- RFC 8999 is effectively complete in live code and tests. The long-header invariant slice is implemented, fuzzed, benchmarked, and already closed out.
- RFC 9000 is mixed. The stream, varint, and packet-header foundation slices already exist, but most transport, frame, and registry work is still greenfield.
- RFC 9001 and RFC 9002 have no live implementation or test surface in `src` or `tests`; they are greenfield apart from the generated canonical spec artifacts and overlap notes.
- Live tests use xUnit `Trait("Requirement", "...")`. The source tree has no `REQ-QUIC-*` refs or XML comments.
- The only live stale requirement IDs are the legacy `REQ-QUIC-HDR`, `REQ-QUIC-VINT`, and `REQ-QUIC-STRM` traits in tests. The RFC 8999 chunk already remapped its live traits to canonical IDs.
- The import audit says there are no true import defects left. The remaining validator issue is namespace-policy mismatch only.

## Repo-Wide Findings

- Test requirement IDs are carried through xUnit traits, for example `Trait("Requirement", "REQ-QUIC-RFC8999-S5P1-0001")`.
- Source code under `src/Incursa.Quic` does not carry requirement IDs in comments or code refs.
- Generated trace and quality artifacts already exist under `specs/generated/quic`, including:
  - `import-audit-summary.md`
  - `import-audit-details.json`
  - `import-missing-coverage.md`
  - `import-validator-mismatch.md`
  - `assembly-summary.md`
  - `assembly-overlap-report.md`
  - `implementation-chunk-manifest.md/json`
  - `chunks/*.reconciliation.md/json`
  - `chunks/*.closeout.md/json`
  - `chunks/*.implementation-summary.md/json`
- Benchmarks already exist for the hot parser paths:
  - `benchmarks/QuicHeaderParsingBenchmarks.cs`
  - `benchmarks/QuicVariableLengthIntegerBenchmarks.cs`
  - `benchmarks/QuicStreamParsingBenchmarks.cs`
- The overlap reports are useful for planning, not as blockers:
  - RFC 8999 section 5.1 is intentionally overlap-prone against RFC 9000 packet-format work.
  - RFC 9000 has retained overlap families around sections 17.2, 17.3.1, 19.4, 19.5, 19.8, 19.10, 19.11, 19.13, and 19.15.
  - RFC 9002 retains the appendix overlap pair `REQ-QUIC-RFC9002-SAP11-0003` / `REQ-QUIC-RFC9002-SBP9-0003`.
- No chunk is stale-only. Every stale legacy ID sits next to live code/tests or a generated review artifact.

## Existing Work By RFC

### RFC 8999

- `RFC8999-01` (`S5P1`) is `implemented_and_tested`.
- Code evidence: `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicPacketParsing.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`, `src/Incursa.Quic/QuicHeaderForm.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicPacketParserTests.cs`, `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`.
- Stale requirement refs: none in the live RFC 8999 slice.
- Confidence: high.
- The generated closeout doc for this chunk says the slice is complete and no stale requirement IDs remain.

### RFC 9000

- `RFC9000-01` (`S2/S2P1/S2P2/S2P3/S2P4`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicStreamId.cs`, `src/Incursa.Quic/QuicStreamType.cs`, `src/Incursa.Quic/QuicStreamFrame.cs`, `src/Incursa.Quic/QuicStreamParser.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicStreamIdTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamIdPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFramePropertyGenerators.cs`, `benchmarks/QuicStreamParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-STRM-0001` through `REQ-QUIC-STRM-0004`.
- Notes: `S2P1` and `S2P2` are already represented; `S2P3` and `S2P4` are still greenfield.
- Confidence: high.

- `RFC9000-02` through `RFC9000-03` (`S3/S4`) are `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Confidence: high.

- `RFC9000-04` (`S5/S5P1/S5P1P1/S5P1P2/S5P2/S5P2P1/S5P2P2/S5P2P3`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicPacketParsing.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-HDR-0008`, `REQ-QUIC-HDR-0009`, `REQ-QUIC-HDR-0010`.
- Notes: packet classification and Version Negotiation parsing exist; CID policy and connection-establishment semantics are still greenfield.
- Confidence: high.

- `RFC9000-05` through `RFC9000-14` (`S5P3/S6/S7/S8/S9/S10/S11/S12/S13/S14`) are `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Confidence: high.

- `RFC9000-15` (`S15/S16/S17/S17P1/S17P2`) is `implemented_and_tested`.
- Code evidence: `src/Incursa.Quic/QuicVariableLengthInteger.cs`, `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`, `src/Incursa.Quic/QuicHeaderForm.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicVariableLengthIntegerTests.cs`, `tests/Incursa.Quic.Tests/QuicVariableLengthIntegerPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicVariableLengthIntegerPropertyGenerators.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`, `benchmarks/QuicVariableLengthIntegerBenchmarks.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-VINT-0001` through `REQ-QUIC-VINT-0005`.
- Notes: the shared stream fuzz file also uses VINT tags because it depends on the varint parser boundary cases.
- Confidence: high.

- `RFC9000-16` (`S17P2P1/S17P2P2`) is `implemented_and_tested`.
- Code evidence: `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-HDR-0008`, `REQ-QUIC-HDR-0009`, `REQ-QUIC-HDR-0010`.
- Notes: Version Negotiation and Initial packet header parsing are live; the surrounding packet-type semantics remain only partially evidenced.
- Confidence: high.

- `RFC9000-17` (`S17P2P3/S17P2P4/S17P2P5/S17P2P5P1/S17P2P5P2/S17P2P5P3`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicLongHeaderPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`.
- Stale requirement refs: none direct.
- Notes: the long-header envelope is present, but 0-RTT, Handshake, and Retry packet semantics remain greenfield.
- Confidence: medium.

- `RFC9000-18` (`S17P3/S17P3P1/S17P4`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicShortHeaderPacket.cs`, `src/Incursa.Quic/QuicPacketParser.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicShortHeaderPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-HDR-0007`.
- Notes: short-header parsing exists; spin-bit observability does not.
- Confidence: high.

- `RFC9000-19` through `RFC9000-20` (`S18/S19P1/S19P2/S19P3/S19P3P1/S19P3P2`) are `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Confidence: high.

- `RFC9000-21` (`S19P4/S19P5/S19P6/S19P7/S19P8`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicStreamFrame.cs`, `src/Incursa.Quic/QuicStreamParser.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFramePropertyGenerators.cs`, `benchmarks/QuicStreamParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-STRM-0005` through `REQ-QUIC-STRM-0011`.
- Notes: STREAM frame parsing is live; RESET_STREAM, STOP_SENDING, and CRYPTO frame formats are still greenfield. The fuzz file also carries shared VINT tags, but those are accounted for under `RFC9000-15`.
- Confidence: high.

- `RFC9000-22` through `RFC9000-26` (`S19P9/S19P10/S19P11/S19P12/S19P13/S19P14/S19P15/S19P16/S19P17/S19P18/S19P19/S19P20/S19P21/S20/S21/S22`) are `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Confidence: high.

### RFC 9001

- `RFC9001-01` (`S2/S3/S4/S5`) is `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Notes: the generated chunk doc treats `S2` as document-convention-only/unclear; there are no live RFC 9001 implementation or test refs.
- Confidence: high.

- `RFC9001-02` (`S6/S7/S8/S9/S10/SB/SBP1P1/SBP1P2/SBP2`) is `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Confidence: high.

### RFC 9002

- `RFC9002-01` through `RFC9002-03` (`S2/S3/S5/S5P1/S5P2/S5P3` and `S6/S6P1/S6P1P1/S6P1P2/S6P2/S6P2P1/S6P2P2/S6P2P2P1/S6P2P3/S6P2P4/S6P3/S6P4` and `S7/S7P1/S7P2/S7P3P1/S7P3P2/S7P3P3/S7P4/S7P5/S7P6/S7P6P1/S7P6P2/S7P7/S7P8`) are `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Confidence: high.

- `RFC9002-04` (`SAP1/SAP1P1/SAP2/SAP4/SAP5/SAP6/SAP7/SAP8/SAP9/SAP10/SAP11`) is `no_evidence` except for the retained overlap note on `SAP11`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Notes: the appendix A/B overlap pair `REQ-QUIC-RFC9002-SAP11-0003` / `REQ-QUIC-RFC9002-SBP9-0003` is intentionally retained for review.
- Confidence: medium.

- `RFC9002-05` (`SBP1/SBP2/SBP3/SBP4/SBP5/SBP6/SBP7/SBP8/SBP9`) is `no_evidence` except for the retained overlap note on `SBP9`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Notes: the same appendix overlap pair is the only retained cross-reference that the import audit still calls out.
- Confidence: medium.

## Recommended Execution Chunks

- `skip`
  - `RFC8999-01`
  - Reason: already implemented, tested, fuzzed, benchmarked, and closed out.

- `prompt2_then_prompt3_then_prompt4`
  - `RFC9000-01`
  - `RFC9000-04`
  - `RFC9000-15`
  - `RFC9000-16`
  - `RFC9000-17`
  - `RFC9000-18`
  - `RFC9000-21`
  - Reason: each chunk has live code or tests, plus legacy requirement IDs or direct overlap with existing parser coverage.

- `prompt3_then_prompt4`
  - `RFC9000-02` through `RFC9000-03`
  - `RFC9000-05` through `RFC9000-14`
  - `RFC9000-19` through `RFC9000-20`
  - `RFC9000-22` through `RFC9000-26`
  - `RFC9001-01` through `RFC9001-02`
  - `RFC9002-01` through `RFC9002-03`
  - Reason: these chunks are greenfield in live code/tests.

- `human_review_first`
  - `RFC9002-04`
  - `RFC9002-05`
  - Reason: the appendix A/B overlap pair is intentionally retained for manual review before automation.

## Recommended First Wave

- `RFC9000-01` - stream abstractions and stream/frame parsing foundation.
- `RFC9000-15` - version numbers, varints, and packet-header wire format foundation.
- `RFC9000-16` - Version Negotiation and Initial packet headers.
- `RFC9000-18` - short-header packet type and spin-bit entry point.
- `RFC9000-21` - RESET_STREAM, STOP_SENDING, CRYPTO, and STREAM frame formats.

`RFC8999-01` is closeout-only and should be skipped rather than scheduled.

## Chunks To Skip

- `RFC8999-01`
  - Already complete in live code/tests and already closed out in generated chunk evidence.

## Chunks That Need Prompt2 First

- `RFC9000-01`
  - Existing stream parser, stream-ID parser, and STREAM-frame tests already exist.
- `RFC9000-04`
  - Existing packet-header and Version Negotiation parser/tests already exist.
- `RFC9000-15`
  - Existing varint parser/tests/benchmarks already exist.
- `RFC9000-16`
  - Existing Version Negotiation and Initial header parser/tests already exist.
- `RFC9000-17`
  - Existing long-header parser/tests overlap this packet-type family, but packet-type semantics remain greenfield.
- `RFC9000-18`
  - Existing short-header parser/tests already exist, but spin-bit observability remains greenfield.
- `RFC9000-21`
  - Existing STREAM-frame parser/tests already exist.

## Chunks That Can Go Straight To Prompt3

- RFC 9000:
  - `RFC9000-02` through `RFC9000-03`
  - `RFC9000-05` through `RFC9000-14`
  - `RFC9000-19` through `RFC9000-20`
  - `RFC9000-22` through `RFC9000-26`
- RFC 9001:
  - `RFC9001-01`
  - `RFC9001-02`
- RFC 9002:
  - `RFC9002-01`
  - `RFC9002-02`
  - `RFC9002-03`

## Chunks Needing Human Review

- `RFC9002-04`
- `RFC9002-05`

These two chunks carry the only retained appendix overlap pair that the import audit still recommends keeping under manual review.
