namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4-0003")]
public sealed class REQ_QUIC_RFC9000_S4_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_ControlsHowManyStreamsAPeerCanInitiate()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(incomingBidirectionalStreamLimit: 1);

        byte[] overLimitPacket = QuicStreamTestData.BuildStreamFrame(0x08, streamId: 5, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(overLimitPacket, out QuicStreamFrame overLimitFrame));

        Assert.False(state.TryReceiveStreamFrame(overLimitFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }
}
