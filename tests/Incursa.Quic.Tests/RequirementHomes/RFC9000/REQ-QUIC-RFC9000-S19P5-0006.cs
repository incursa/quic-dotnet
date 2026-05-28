// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
public sealed class REQ_QUIC_RFC9000_S19P5_0006
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStopSendingFrame_DecodesVariableLengthStreamIdField()
    {
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildStopSendingPayload(
            QuicVarintTestData.EncodeMinimal(0x05),
            QuicVarintTestData.EncodeWithLength(0x1234, 2),
            QuicVarintTestData.EncodeMinimal(0x55));

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(0x1234UL, parsed.StreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStopSendingFrame_RejectsTruncatedStreamIdField()
    {
        byte[] streamId = QuicVarintTestData.EncodeWithLength(0x1234, 2);
        byte[] encoded = QuicStreamControlFrameTestSupport.BuildStopSendingPayload(
            QuicVarintTestData.EncodeMinimal(0x05),
            streamId[..1],
            QuicVarintTestData.EncodeMinimal(0x55));

        Assert.False(QuicFrameCodec.TryParseStopSendingFrame(encoded, out _, out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0006")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStopSendingFrame_RoundTripsMaximumStreamIdField()
    {
        QuicStopSendingFrame frame = new(
            QuicVariableLengthInteger.MaxValue,
            applicationProtocolErrorCode: 0x55);
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(frame);

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.StreamId);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicFrameCodec.TryFormatStopSendingFrame(parsed, destination, out int bytesWritten));
        Assert.True(encoded.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }
}
