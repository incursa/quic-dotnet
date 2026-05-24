namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S3-0007")]
public sealed class REQ_QUIC_RFC9221_S3_0007
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9221-S3-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedOneRttDatagramFrame_ClosesWhenFrameExceedsAdvertisedLocalLimit()
    {
        using QuicConnectionRuntime runtime = QuicDatagramRuntimeTestSupport.CreateFinishedRuntime(
            localMaxDatagramFrameSize: 2);

        QuicConnectionTransitionResult result = QuicDatagramRuntimeTestSupport.ReceiveProtectedDatagramFrame(
            runtime,
            new QuicDatagramFrame
            {
                FrameType = QuicFrameCodec.DatagramWithLengthFrameType,
                DatagramData = [0x61, 0x62],
            });

        Assert.True(result.StateChanged);
        QuicConnectionTerminalState terminalState = Assert.IsType<QuicConnectionTerminalState>(runtime.TerminalState);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, terminalState.Close.TransportErrorCode);
        Assert.Equal(QuicFrameCodec.DatagramWithLengthFrameType, terminalState.Close.TriggeringFrameType);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDeliverDatagramEffect);
    }
}
