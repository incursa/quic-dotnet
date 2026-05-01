namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0074")]
public sealed class REQ_QUIC_CRT_0074
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EstablishingAndActivePhasesAllowOrdinarySending()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime runtime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.CanSendOrdinaryPackets);

        runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.CanSendOrdinaryPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TerminalPhasesDoNotAllowOrdinarySending()
    {
        QuicCrtLifecycleClock clock = new(0);
        using QuicConnectionRuntime closingRuntime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);
        using QuicConnectionRuntime drainingRuntime = QuicCrtLifecycleRequirementTestSupport.CreateRuntime(clock);

        QuicCrtLifecycleRequirementTestSupport.RequestLocalClose(closingRuntime);
        QuicCrtLifecycleRequirementTestSupport.ReceivePeerClose(drainingRuntime);

        Assert.Equal(QuicConnectionPhase.Closing, closingRuntime.Phase);
        Assert.Equal(QuicConnectionSendingMode.CloseOnly, closingRuntime.SendingMode);
        Assert.False(closingRuntime.CanSendOrdinaryPackets);

        Assert.Equal(QuicConnectionPhase.Draining, drainingRuntime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, drainingRuntime.SendingMode);
        Assert.False(drainingRuntime.CanSendOrdinaryPackets);
    }
}
