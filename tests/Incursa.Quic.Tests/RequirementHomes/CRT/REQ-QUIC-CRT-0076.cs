namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0076")]
public sealed class REQ_QUIC_CRT_0076
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DrainingDoesNotEmitPacketsForLaterDatagrams()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.77", RemotePort: 443);

        QuicCrtLifecycleRequirementTestSupport.ObservePath(runtime, pathIdentity);
        QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(runtime, nowTicks: 2);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 3);

        Assert.Equal(QuicConnectionPhase.Draining, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.False(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void DiscardedDoesNotEmitPacketsForLaterDatagrams()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);
        QuicConnectionPathIdentity pathIdentity = new("203.0.113.78", RemotePort: 443);

        QuicCrtLifecycleRequirementTestSupport.ObservePath(runtime, pathIdentity);
        QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(runtime, nowTicks: 2);
        QuicCrtLifecycleRequirementTestSupport.ExpireCloseLifetime(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                pathIdentity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 3);

        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.False(result.StateChanged);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }
}
