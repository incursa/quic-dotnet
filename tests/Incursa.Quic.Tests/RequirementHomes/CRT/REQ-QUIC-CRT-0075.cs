namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0075")]
public sealed class REQ_QUIC_CRT_0075
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosingLimitsSendingToConnectionCloseDatagrams()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.75", RemotePort: 443);

        QuicCrtLifecycleRequirementTestSupport.ObservePath(
            runtime,
            pathIdentity,
            QuicCrtLifecycleRequirementTestSupport.MicrosecondsToTicks(50));

        QuicConnectionTransitionResult result = QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(
            runtime,
            QuicCrtLifecycleRequirementTestSupport.MicrosecondsToTicks(75));

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);

        QuicConnectionSendDatagramEffect send = Assert.IsType<QuicConnectionSendDatagramEffect>(
            Assert.Single(result.Effects, effect => effect is QuicConnectionSendDatagramEffect));

        Assert.Equal(pathIdentity, send.PathIdentity);
        Assert.True(QuicFrameCodec.TryParseConnectionCloseFrame(
            send.Datagram.Span,
            out QuicConnectionCloseFrame closeFrame,
            out int bytesConsumed));
        Assert.Equal(send.Datagram.Length, bytesConsumed);
        Assert.False(closeFrame.IsApplicationError);
        Assert.Equal((ulong)QuicTransportErrorCode.NoError, closeFrame.ErrorCode);
        Assert.Equal(0x1cUL, closeFrame.TriggeringFrameType);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosingDoesNotFlushOrdinaryPacketProcessingForAttributedPackets()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.76", RemotePort: 443);

        QuicCrtLifecycleRequirementTestSupport.ObservePath(runtime, pathIdentity);
        QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(runtime, nowTicks: 2);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 3);

        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, runtime.SendingMode);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionUpdateEndpointBindingsEffect);
    }
}
