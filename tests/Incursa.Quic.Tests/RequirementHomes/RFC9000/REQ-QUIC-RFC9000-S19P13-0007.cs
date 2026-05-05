namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
public sealed class REQ_QUIC_RFC9000_S19P13_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamDataBlockedFrame_PreservesTheBlockedStreamId()
    {
        ulong blockedStreamId = 0x1234UL;
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(streamId: blockedStreamId);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(encoded, blockedStreamId, expectedMaximumStreamData: 16);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamDataBlockedFrame_PreservesTheMaximumVarintBlockedStreamId()
    {
        ulong blockedStreamId = QuicVariableLengthInteger.MaxValue;
        byte[] encoded = QuicS19P13StreamDataBlockedFrameTestSupport.BuildStreamDataBlockedFrame(streamId: blockedStreamId);

        QuicS19P13StreamDataBlockedFrameTestSupport.AssertParses(encoded, blockedStreamId, expectedMaximumStreamData: 16);
        Assert.Equal(1 + QuicVariableLengthInteger.MaxEncodedLength + 1, encoded.Length);
        QuicS19P13StreamDataBlockedFrameTestSupport.AssertFormats(new QuicStreamDataBlockedFrame(blockedStreamId, 16), encoded);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P13-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatStreamDataBlockedFrame_RejectsBlockedStreamIdsAboveTheVarintRange()
    {
        QuicStreamDataBlockedFrame frame = new(QuicVariableLengthInteger.MaxValue + 1, maximumStreamData: 16);
        Span<byte> destination = stackalloc byte[24];

        Assert.False(QuicFrameCodec.TryFormatStreamDataBlockedFrame(frame, destination, out _));
    }
}
