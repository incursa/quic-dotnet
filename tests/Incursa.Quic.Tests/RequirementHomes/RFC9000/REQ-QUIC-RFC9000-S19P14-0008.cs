namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
public sealed class REQ_QUIC_RFC9000_S19P14_0008
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStreamsBlockedFrame_AcceptsMaximumStreamsBelowTheAllowedLimit()
    {
        ulong maximumStreams = QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit - 1;
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(maximumStreams: maximumStreams);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedIsBidirectional: true,
            expectedMaximumStreams: maximumStreams);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseStreamsBlockedFrame_RejectsMaximumStreamsAboveTheAllowedLimit()
    {
        QuicStreamsBlockedFrame frame = new(true, QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit + 1);
        byte[] encoded = QuicFrameTestData.BuildStreamsBlockedFrame(frame);

        Assert.False(QuicFrameCodec.TryParseStreamsBlockedFrame(encoded, out _, out _));
        Assert.False(QuicFrameCodec.TryFormatStreamsBlockedFrame(frame, stackalloc byte[16], out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P14-0008")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStreamsBlockedFrame_AcceptsMaximumStreamsAtTheAllowedLimit()
    {
        ulong maximumStreams = QuicS19P14StreamsBlockedFrameTestSupport.MaximumStreamLimit;
        byte[] encoded = QuicS19P14StreamsBlockedFrameTestSupport.BuildStreamsBlockedFrame(maximumStreams: maximumStreams);

        QuicS19P14StreamsBlockedFrameTestSupport.AssertParses(
            encoded,
            expectedIsBidirectional: true,
            expectedMaximumStreams: maximumStreams);
        QuicS19P14StreamsBlockedFrameTestSupport.AssertFormats(
            new QuicStreamsBlockedFrame(isBidirectional: true, maximumStreams: maximumStreams),
            encoded);
    }
}
