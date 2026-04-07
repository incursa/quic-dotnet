namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0001")]
public sealed class REQ_QUIC_RFC9000_S4P6_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_LimitsTheCumulativeNumberOfIncomingStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(incomingBidirectionalStreamLimit: 1);

        byte[] overLimitPacket = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 5, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(overLimitPacket, out QuicStreamFrame overLimitFrame));

        Assert.False(state.TryReceiveStreamFrame(overLimitFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }
}
