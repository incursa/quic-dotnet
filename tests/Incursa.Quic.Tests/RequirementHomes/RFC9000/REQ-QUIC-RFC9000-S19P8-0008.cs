// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P8-0008")]
public sealed class REQ_QUIC_RFC9000_S19P8_0008
{
    [Theory]
    [InlineData((byte)0x08)]
    [InlineData((byte)0x09)]
    [InlineData((byte)0x0A)]
    [InlineData((byte)0x0B)]
    [InlineData((byte)0x0C)]
    [InlineData((byte)0x0D)]
    [InlineData((byte)0x0E)]
    [InlineData((byte)0x0F)]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseStreamFrame_AcceptsRegisteredStreamFrameTypes(byte frameType)
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType,
            streamId: 0x04,
            streamData: [0xAA],
            offset: (frameType & QuicStreamFrameBits.OffsetBitMask) != 0 ? 1UL : 0UL);

        Assert.Equal(frameType, frame.FrameType);
    }

    [Theory]
    [InlineData((byte)0x08)]
    [InlineData((byte)0x0F)]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryParseStreamFrame_AcceptsStreamFrameTypeBoundaries(byte frameType)
    {
        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType,
            streamId: 0x04,
            streamData: [0xAA],
            offset: (frameType & QuicStreamFrameBits.OffsetBitMask) != 0 ? 1UL : 0UL);

        Assert.Equal(frameType, frame.FrameType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsFramesWithNonStreamTypes()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x06, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x07, 0x00], out _));
        Assert.False(QuicStreamParser.TryParseStreamFrame([0x10, 0x00], out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsEmptyInput()
    {
        Assert.False(QuicStreamParser.TryParseStreamFrame(Array.Empty<byte>(), out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseStreamFrame_RejectsNonShortestFrameTypeEncoding()
    {
        byte[] packet = QuicStreamTestData.BuildStreamFrameWithEncodedType(
            frameType: 0x08,
            encodedLength: 2,
            streamId: 0x00,
            streamData: [0x00, 0x00]);

        Assert.False(QuicStreamParser.TryParseStreamFrame(packet, out _));
    }
}
