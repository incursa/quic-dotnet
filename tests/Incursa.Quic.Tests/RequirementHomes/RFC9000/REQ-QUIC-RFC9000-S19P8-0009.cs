// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0009")]
public sealed class REQ_QUIC_RFC9000_S19P8_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_ParsesVariableLengthStreamId()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: 0x1234,
            streamData: [0xAA]);

        Assert.Equal(0x1234UL, frame.StreamId.Value);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_ParsesLargestVariableLengthStreamId()
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: QuicVariableLengthInteger.MaxValue,
            streamData: []);

        Assert.Equal(QuicVariableLengthInteger.MaxValue, frame.StreamId.Value);
        Assert.Equal(0, frame.StreamDataLength);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsTruncatedFixedFields(int truncateBy)
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrame(
            frameType: 0x0F,
            streamId: 0x04,
            streamData: [0xAA, 0xBB],
            offset: 0x11223344);

        byte[] truncated = packet[..Math.Max(0, packet.Length - truncateBy)];

        Assert.False(QuicStreamParser.TryParseStreamFrame(truncated, out _));
    }
}
