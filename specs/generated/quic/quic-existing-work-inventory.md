# QUIC Existing Work Inventory

## Executive Summary

- RFC 8999 is effectively complete in live code and tests. The long-header invariant slice is implemented, fuzzed, benchmarked, and already closed out.
- RFC 9000 is mixed. The stream, varint, packet-header, transport-parameter, address-validation, path-validation, idle-timeout, stateless-reset, ACK, and recovery helper slices already exist, but stream state, flow control, connection lifecycle, migration, and the remaining transport-control slices are still incomplete. The next bounded stream-helper slice is now defined around connection-scoped stream opening, ordered receive buffering, final-size accounting, and MAX_* flow-control application.
- RFC 9001 is helper-layer partial. AEAD usage-limit helpers and tests exist, but packet-protection, key-derivation, and key-update work are still end-to-end gaps.
- RFC 9002 is helper-layer partial. RTT, recovery-timing, congestion-control, ACK/recovery bookkeeping, and related helper surfaces exist, but sender orchestration and PTO integration are still incomplete.
- Live tests use xUnit `Trait("Requirement", "...")` plus requirement-owned homes. The source tree also carries helper-layer implementation refs for RFC 9000, RFC 9001, and RFC 9002 slices.
- The remaining stale requirement IDs are concentrated in older packet-header and stream-trace slices. The RFC 8999 chunk already remapped its live traits to canonical IDs.
- The import audit still reports mostly proof-shape and namespace-policy issues rather than import defects.

## Repo-Wide Findings

- Test requirement IDs are carried through xUnit traits, for example `Trait("Requirement", "REQ-QUIC-RFC8999-S5P1-0001")`.
- Source code under `src/Incursa.Quic` does not carry requirement IDs in comments or code refs, but it does now expose the helper-layer implementation surfaces that backfill several later RFC 9000/9001/9002 slices.
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

- `RFC9000-02` through `RFC9000-03` (`S3/S4`) are `partial`.
- Code evidence: `src/Incursa.Quic/QuicConnectionStreamState.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicConnectionStreamStateTests.cs`, `tests/Incursa.Quic.Tests/QuicConnectionStreamStatePropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicConnectionStreamStateFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFramePropertyGenerators.cs`.
- Stale requirement refs: none.
- Notes: helper-layer connection-scoped stream accounting now exists, including stream-open counting, ordered receive buffering, final-size bookkeeping, monotonic MAX_* application, and blocked-frame snapshots; application-facing stream APIs plus end-to-end STOP_SENDING/RESET coordination remain blocked.
- Confidence: high.

- `RFC9000-04` (`S5/S5P1/S5P1P1/S5P1P2/S5P2/S5P2P1/S5P2P2/S5P2P3`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicPacketParser.cs`, `src/Incursa.Quic/QuicPacketParsing.cs`, `src/Incursa.Quic/QuicLongHeaderPacket.cs`, `src/Incursa.Quic/QuicVersionNegotiationPacket.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicHeaderPropertyTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicVersionNegotiationPacketTests.cs`, `tests/Incursa.Quic.Tests/QuicHeaderPropertyGenerators.cs`, `benchmarks/QuicHeaderParsingBenchmarks.cs`.
- Stale requirement refs: legacy header ID 0008, legacy header ID 0009, legacy header ID 0010.
- Notes: packet classification and Version Negotiation parsing exist; CID policy and connection-establishment semantics are still greenfield.
- Confidence: high.

- `RFC9000-05` through `RFC9000-14` (`S5P3/S6/S6P1/S6P2/S6P3/S7/S7P2/S7P3/S7P4/S7P4P1/S7P4P2/S7P5/S8/S8P1/S8P1P1/S8P1P2/S8P1P3/S8P1P4/S8P2/S8P2P1/S8P2P2/S8P2P3/S8P2P4/S9/S9P1/S9P2/S9P3/S9P3P1/S9P3P2/S9P3P3/S9P4/S9P5/S9P6/S9P6P1/S9P6P2/S9P6P3/S9P7/S10/S10P1/S10P1P1/S10P1P2/S10P2/S10P2P1/S10P2P2/S10P2P3/S10P3/S10P3P1/S10P3P2/S10P3P3/S11/S11P1/S11P2/S12P1/S12P2/S12P3/S12P4/S12P5/S13/S13P1/S13P2/S13P2P1/S13P2P2/S13P2P3/S13P2P4/S13P2P5/S13P2P6/S13P2P7/S13P3/S13P4/S13P4P1/S13P4P2/S13P4P2P1/S13P4P2P2/S14/S14P1/S14P2/S14P2P1/S14P3/S14P4`) are `partial`.
- Code evidence: `src/Incursa.Quic/QuicAddressValidation.cs`, `src/Incursa.Quic/QuicAntiAmplificationBudget.cs`, `src/Incursa.Quic/QuicIdleTimeoutState.cs`, `src/Incursa.Quic/QuicPathValidation.cs`, `src/Incursa.Quic/QuicStatelessReset.cs`, `src/Incursa.Quic/QuicAckGenerationState.cs`, `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/QuicRttEstimator.cs`, `src/Incursa.Quic/QuicCongestionControlState.cs`, `src/Incursa.Quic/QuicTransportParametersCodec.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicAddressValidationTests.cs`, `tests/Incursa.Quic.Tests/QuicAntiAmplificationBudgetTests.cs`, `tests/Incursa.Quic.Tests/QuicIdleTimeoutStateTests.cs`, `tests/Incursa.Quic.Tests/QuicPathValidationTests.cs`, `tests/Incursa.Quic.Tests/QuicStatelessResetTests.cs`, `tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`, `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs`, `tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs`, `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`, `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`, `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`.
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
- Stale requirement refs: legacy header ID 0008, legacy header ID 0009, legacy header ID 0010.
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
- Stale requirement refs: legacy header ID 0007.
- Notes: short-header parsing exists; spin-bit observability does not.
- Confidence: high.

- `RFC9000-19` through `RFC9000-20` (`S18/S18P1/S18P2/S19P1/S19P2/S19P3/S19P3P1/S19P3P2`) are `partial`.
- Code evidence: `src/Incursa.Quic/QuicTransportParametersCodec.cs`, `src/Incursa.Quic/QuicFrameCodec.cs`, `src/Incursa.Quic/QuicAckGenerationState.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicTransportParametersTests.cs`, `tests/Incursa.Quic.Tests/QuicTransportParametersFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecTests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicAckGenerationStateTests.cs`.
- Stale requirement refs: none.
- Confidence: high.

- `RFC9000-21` (`S19P4/S19P5/S19P6/S19P7/S19P8`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicResetStreamFrame.cs`, `src/Incursa.Quic/QuicStopSendingFrame.cs`, `src/Incursa.Quic/QuicCryptoFrame.cs`, `src/Incursa.Quic/QuicStreamFrame.cs`, `src/Incursa.Quic/QuicStreamParser.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicFrameCodecPart3Tests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFrameTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicStreamFramePropertyGenerators.cs`, `benchmarks/QuicStreamParsingBenchmarks.cs`.
- Stale requirement refs: `REQ-QUIC-STRM-0005` through `REQ-QUIC-STRM-0011`.
- Notes: STREAM frame parsing is live; RESET_STREAM, STOP_SENDING, and CRYPTO frame helper/codecs are also present, but the end-to-end transport orchestration is still missing. The fuzz file also carries shared VINT tags, but those are accounted for under `RFC9000-15`.
- Confidence: high.

- `RFC9000-22` through `RFC9000-26` (`S19P9/S19P10/S19P11/S19P12/S19P13/S19P14/S19P15/S19P16/S19P17/S19P18/S19P19/S19P20/S19P21/S20P1/S20P2/S21P1P1P1/S21P2/S21P3/S21P4/S21P5/S21P5P3/S21P5P6/S21P6/S21P7/S21P9/S21P10/S21P11/S21P12/S22P1P1/S22P1P2/S22P1P3/S22P1P4/S22P2/S22P3/S22P4/S22P5`) are `partial`.
- Code evidence: `src/Incursa.Quic/QuicDataBlockedFrame.cs`, `src/Incursa.Quic/QuicMaxDataFrame.cs`, `src/Incursa.Quic/QuicMaxStreamDataFrame.cs`, `src/Incursa.Quic/QuicMaxStreamsFrame.cs`, `src/Incursa.Quic/QuicStreamDataBlockedFrame.cs`, `src/Incursa.Quic/QuicStreamsBlockedFrame.cs`, `src/Incursa.Quic/QuicNewConnectionIdFrame.cs`, `src/Incursa.Quic/QuicRetireConnectionIdFrame.cs`, `src/Incursa.Quic/QuicPathChallengeFrame.cs`, `src/Incursa.Quic/QuicPathResponseFrame.cs`, `src/Incursa.Quic/QuicConnectionCloseFrame.cs`, `src/Incursa.Quic/QuicHandshakeDoneFrame.cs`, `src/Incursa.Quic/QuicTransportErrorCode.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicFrameCodecPart4Tests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecPart4FuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingTests.cs`, `tests/Incursa.Quic.Tests/QuicFrameCodecErrorHandlingFuzzTests.cs`, `tests/Incursa.Quic.Tests/QuicTransportErrorCodeTests.cs`, `tests/Incursa.Quic.Tests/QuicPathValidationTests.cs`.
- Stale requirement refs: none.
- Confidence: high.

### RFC 9001

- `RFC9001-01` (`S2/S3/S4/S5`) is `no_evidence`.
- Code evidence: none in live `src`.
- Test evidence: none in live `tests`.
- Stale requirement refs: none.
- Notes: the generated chunk doc treats `S2` as document-convention-only/unclear; there are no live RFC 9001 implementation or test refs.
- Confidence: high.

- `RFC9001-02` (`S6/S7/S8/S9/S10/SB/SBP1P1/SBP1P2/SBP2`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicAeadAlgorithm.cs`, `src/Incursa.Quic/QuicAeadPacketSizeProfile.cs`, `src/Incursa.Quic/QuicAeadUsageLimitCalculator.cs`, `src/Incursa.Quic/QuicAeadUsageLimits.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicAeadUsageLimitCalculatorTests.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-SB-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-SBP1P1-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9001/REQ-QUIC-RFC9001-SBP1P2-0001.cs`.
- Stale requirement refs: none.
- Confidence: high.

### RFC 9002

- `RFC9002-01` through `RFC9002-03` (`S2/S3/S5/S5P1/S5P2/S5P3` and `S6/S6P1/S6P1P1/S6P1P2/S6P2/S6P2P1/S6P2P2/S6P2P2P1/S6P2P3/S6P2P4/S6P3/S6P4` and `S7/S7P1/S7P2/S7P3P1/S7P3P2/S7P3P3/S7P4/S7P5/S7P6/S7P6P1/S7P6P2/S7P7/S7P8`) are `partial`.
- Code evidence: `src/Incursa.Quic/QuicRttEstimator.cs`, `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/QuicCongestionControlState.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicRttEstimatorTests.cs`, `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs`, `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`.
- Stale requirement refs: none.
- Confidence: high.

- `RFC9002-04` (`SAP1/SAP1P1/SAP2/SAP4/SAP5/SAP6/SAP7/SAP8/SAP9/SAP10/SAP11`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicRecoveryTiming.cs`, `src/Incursa.Quic/QuicCongestionControlState.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicRecoveryTimingTests.cs`, `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/REQ-QUIC-RFC9002-SAP11-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/REQ-QUIC-RFC9002-SAP11-0002.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/REQ-QUIC-RFC9002-SAP11-0003.cs`.
- Stale requirement refs: none.
- Notes: the appendix A/B overlap pair `REQ-QUIC-RFC9002-SAP11-0003` / `REQ-QUIC-RFC9002-SBP9-0003` is intentionally retained for review.
- Confidence: medium.

- `RFC9002-05` (`SBP1/SBP2/SBP3/SBP4/SBP5/SBP6/SBP7/SBP8/SBP9`) is `partial`.
- Code evidence: `src/Incursa.Quic/QuicCongestionControlState.cs`, `src/Incursa.Quic/QuicAeadUsageLimitCalculator.cs`.
- Test evidence: `tests/Incursa.Quic.Tests/QuicCongestionControlStateTests.cs`, `tests/Incursa.Quic.Tests/QuicAeadUsageLimitCalculatorTests.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/REQ-QUIC-RFC9002-SBP9-0001.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/REQ-QUIC-RFC9002-SBP9-0002.cs`, `tests/Incursa.Quic.Tests/RequirementHomes/RFC9002/REQ-QUIC-RFC9002-SBP9-0003.cs`.
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
  - `RFC9000-05` through `RFC9000-14`
  - `RFC9000-15`
  - `RFC9000-16`
  - `RFC9000-17`
  - `RFC9000-18`
  - `RFC9000-19` through `RFC9000-20`
  - `RFC9000-21`
  - `RFC9000-22` through `RFC9000-26`
  - `RFC9001-02`
  - `RFC9002-01` through `RFC9002-03`
  - Reason: these chunks now have live helper-layer code or tests and should reconcile existing evidence before broader implementation work.

- `prompt2_then_prompt3_then_prompt4`
  - `RFC9000-02` through `RFC9000-03`
  - `RFC9001-01`
  - Reason: these chunks now have live helper-layer code or tests and should reconcile existing evidence before broader implementation work.

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
- `RFC9000-02` through `RFC9000-03`
  - Existing helper-layer connection-scoped stream accounting and flow-control tests now exist.
- `RFC9000-04`
  - Existing packet-header and Version Negotiation parser/tests already exist.
- `RFC9000-05`
  - Existing helper-layer code for address validation, anti-amplification, transport parameters, and path validation already exists.
- `RFC9000-09`
  - Existing helper-layer code for idle timeout and connection close/lifecycle tracking already exists.
- `RFC9000-10`
  - Existing helper-layer stateless-reset code and tests already exist.
- `RFC9000-12`
  - Existing ACK-generation helpers already exist.
- `RFC9000-13`
  - Existing recovery-timing and congestion-control helpers already exist.
- `RFC9000-15`
  - Existing varint parser/tests/benchmarks already exist.
- `RFC9000-16`
  - Existing Version Negotiation and Initial header parser/tests already exist.
- `RFC9000-17`
  - Existing long-header parser/tests overlap this packet-type family, but packet-type semantics remain greenfield.
- `RFC9000-18`
  - Existing short-header parser/tests already exist, but spin-bit observability remains greenfield.
- `RFC9000-19`
  - Existing transport-parameter codec/helpers already exist.
- `RFC9000-20`
  - Existing ACK and frame-codec helpers already exist.
- `RFC9000-21`
  - Existing STREAM-frame parser/tests already exist.
- `RFC9000-22`
  - Existing flow-control frame helpers already exist.
- `RFC9000-23`
  - Existing connection-ID and path-probe frame helpers already exist.
- `RFC9000-24`
  - Existing connection-close and handshake-done frame helpers already exist.
- `RFC9000-25`
  - Existing transport-error code helpers already exist.
- `RFC9001-02`
  - Existing AEAD usage-limit helpers already exist.
- `RFC9002-01`
  - Existing RTT-estimation helpers already exist.
- `RFC9002-02`
  - Existing loss-detection and PTO-timing helpers already exist.
- `RFC9002-03`
  - Existing congestion-control helpers already exist.

## Chunks That Can Go Straight To Prompt3

- RFC 9001:
  - `RFC9001-01`

## Chunks Needing Human Review

- `RFC9002-04`
- `RFC9002-05`

These two chunks carry the only retained appendix overlap pair that the import audit still recommends keeping under manual review.
