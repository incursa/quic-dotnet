namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
public sealed class REQ_QUIC_RFC9000_S19P13_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamDataBlockedFrame_ParsesTheStreamIdVarint()
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(streamId: 0x1234);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(encoded, expectedStreamId: 0x1234, expectedMaximumStreamData: 16);
    }

    [Theory]
    [InlineData(0x3FUL, 1)]
    [InlineData(0x40UL, 2)]
    [InlineData(0x3FFFUL, 2)]
    [InlineData(0x4000UL, 4)]
    [InlineData(0x3FFF_FFFFUL, 4)]
    [InlineData(0x4000_0000UL, 8)]
    [InlineData(QuicVariableLengthInteger.MaxValue, 8)]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamDataBlockedFrame_AcceptsAllStreamIdVarintLengths(
        ulong streamId,
        int expectedStreamIdFieldLength)
    {
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(streamId);

        Assert.True(QuicFrameCodec.TryParseStreamDataBlockedFrame(
            encoded,
            out QuicStreamDataBlockedFrame frame,
            out int bytesConsumed));

        Assert.Equal(streamId, frame.StreamId);
        Assert.Equal(16UL, frame.MaximumStreamData);
        Assert.Equal(1 + expectedStreamIdFieldLength + 1, bytesConsumed);
        QuicS19P13StreamDataBlockedFrameTestSupport.AssertFormats(frame, encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamDataBlockedFrame_RejectsTruncatedStreamIdVarints()
    {
        byte[][] truncatedStreamIdFields =
        [
            [0x40],
            [0x80, 0x00, 0x00],
            [0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ];

        foreach (byte[] encodedStreamId in truncatedStreamIdFields)
        {
            byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrameWithTruncatedEncodedStreamId(encodedStreamId);

            QuicS19P13StreamDataBlockedFrameTestSupport.AssertRejects(encoded);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStreamDataBlockedFrame_RejectsStreamIdAboveTheVarintRange()
    {
        QuicStreamDataBlockedFrame frame = new(QuicVariableLengthInteger.MaxValue + 1, maximumStreamData: 16);
        Span<byte> destination = stackalloc byte[24];

        Assert.False(QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, destination, out _));
    }
}
