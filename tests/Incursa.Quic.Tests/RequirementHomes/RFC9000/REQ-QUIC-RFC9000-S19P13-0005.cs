// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
public sealed class REQ_QUIC_RFC9000_S19P13_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamDataBlockedFrame_ParsesTheMaximumStreamDataVarint()
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(maximumStreamData: 0x1234);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(encoded, expectedStreamId: 4, expectedMaximumStreamData: 0x1234);
    }

    [Theory]
    [InlineData(0x3FUL, 1)]
    [InlineData(0x40UL, 2)]
    [InlineData(0x3FFFUL, 2)]
    [InlineData(0x4000UL, 4)]
    [InlineData(0x3FFF_FFFFUL, 4)]
    [InlineData(0x4000_0000UL, 8)]
    [InlineData(QuicVariableLengthInteger.MaxValue, 8)]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamDataBlockedFrame_AcceptsAllMaximumStreamDataVarintLengths(
        ulong maximumStreamData,
        int expectedMaximumStreamDataFieldLength)
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(maximumStreamData: maximumStreamData);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(
            encoded,
            out QuicStreamDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(4UL, frame.StreamId);
        Assert.Equal(maximumStreamData, frame.MaximumStreamData);
        Assert.Equal(1 + 1 + expectedMaximumStreamDataFieldLength, bytesConsumed);
        QuicS19P13StreamDataBlockedFrameTestSupport.AssertFormats(frame, encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamDataBlockedFrame_RejectsTruncatedMaximumStreamDataVarints()
    {
        byte[][] truncatedMaximumStreamDataFields =
        [
            [0x40],
            [0x80, 0x00, 0x00],
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        foreach (byte[] encodedMaximumStreamData in truncatedMaximumStreamDataFields)
        {
            byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrameWithEncodedMaximumStreamData(encodedMaximumStreamData);

            QuicS19P13StreamDataBlockedFrameTestSupport.AssertRejects(encoded);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStreamDataBlockedFrame_RejectsMaximumStreamDataAboveTheVarintRange()
    {
        QuicStreamDataBlockedFrame frame = new(streamId: 4, maximumStreamData: QuicVariableLengthInteger.MaxValue + 1);
        Span<byte> destination = stackalloc byte[24];

        Assert.False(QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, destination, out _));
    }
}
