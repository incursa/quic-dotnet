// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_FrameLegality_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0720")]
    [Requirement("REQ-QUIC-RFC9000-0724")]
    [Requirement("REQ-QUIC-RFC9000-0734")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void FrameTypePrefixFuzz_UsesTheLeadingShortestFrameTypeToIdentifyEachFrame()
    {
        foreach ((ulong ExpectedFrameType, byte[] EncodedFrame) testCase in new (ulong, byte[])[]
        {
            (0x00UL, QuicFrameTestData.BuildPaddingFrame()),
            (0x01UL, QuicFrameTestData.BuildPingFrame()),
            (0x10UL, QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(0x1234))),
            (0x1AUL, QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame([1, 2, 3, 4, 5, 6, 7, 8]))),
            (0x1BUL, QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame([8, 7, 6, 5, 4, 3, 2, 1]))),
        })
        {
            Assert.True(QuicVariableLengthInteger.TryParse(
                testCase.EncodedFrame,
                out ulong parsedFrameType,
                out int frameTypeBytesConsumed));
            Assert.Equal(testCase.ExpectedFrameType, parsedFrameType);
            Assert.Equal(1, frameTypeBytesConsumed);
        }

        foreach (int encodedLength in new[] { 2, 4, 8 })
        {
            Assert.False(QuicFrameCodec.TryParsePingFrame(
                QuicVarintTestData.EncodeWithLength(0x01, encodedLength),
                out _));
            Assert.False(QuicFrameCodec.TryParseMaxDataFrame(
                [.. QuicVarintTestData.EncodeWithLength(0x10, encodedLength), 0x01],
                out _,
                out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0726")]
    [Requirement("REQ-QUIC-RFC9000-0736")]
    [Requirement("REQ-QUIC-RFC9000-0741")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PacketNumberSpaceFrameLegalityFuzz_SeparatesAlwaysAllowedFramesFromApplicationOnlyFrames()
    {
        foreach (byte[] alwaysAllowedFrame in new[]
        {
            QuicFrameTestData.BuildPaddingFrame(),
            QuicFrameTestData.BuildPingFrame(),
            QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA, 0xBB])),
        })
        {
            Assert.True(QuicPacketFrameLegality.TryReadApplicationFrameType(alwaysAllowedFrame, out ulong frameType));
            Assert.False(QuicPacketFrameLegality.IsHandshakePacketForbiddenFrameType(frameType));
        }

        foreach (byte[] applicationOnlyFrame in new[]
        {
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
            QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(100)),
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, [0x11], offset: 0),
            QuicFrameTestData.BuildDatagramFrame(new QuicDatagramFrame(QuicFrameCodec.DatagramWithLengthFrameType, new byte[] { 0x22, 0x33 })),
            QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame([1, 2, 3, 4, 5, 6, 7, 8])),
            QuicFrameTestData.BuildHandshakeDoneFrame(),
        })
        {
            Assert.True(QuicPacketFrameLegality.TryReadApplicationFrameType(applicationOnlyFrame, out ulong frameType));
            Assert.True(QuicPacketFrameLegality.IsHandshakePacketForbiddenFrameType(frameType));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0727")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ForbiddenHandshakeFrameFuzz_ReportsProtocolViolationForDisallowedFrameTypes()
    {
        foreach (byte[] forbiddenHandshakePayload in new[]
        {
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 1, 0)),
            QuicFrameTestData.BuildMaxDataFrame(new QuicMaxDataFrame(100)),
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, [0x11], offset: 0),
            QuicFrameTestData.BuildDatagramFrame(new QuicDatagramFrame(QuicFrameCodec.DatagramWithLengthFrameType, new byte[] { 0x22, 0x33 })),
            QuicFrameTestData.BuildPathResponseFrame(new QuicPathResponseFrame([8, 7, 6, 5, 4, 3, 2, 1])),
            QuicFrameTestData.BuildHandshakeDoneFrame(),
        })
        {
            Assert.Equal(
                QuicWeaklyProtectedPacketPayloadValidationResult.ConnectionError,
                QuicPacketFrameLegality.ValidateWeaklyProtectedHandshakePayload(
                    forbiddenHandshakePayload,
                    QuicTlsEncryptionLevel.Handshake));
        }
    }
}
