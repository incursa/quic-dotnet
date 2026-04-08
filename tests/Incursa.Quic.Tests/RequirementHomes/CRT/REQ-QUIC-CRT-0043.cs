namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0043")]
public sealed class REQ_QUIC_CRT_0043
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void FatalTlsAlertsAreConvertedIntoConnectionCloseLifecycleTransitions()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.FatalAlert,
                    AlertDescription: 42)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TlsState.FatalAlertCode);
        Assert.Equal("TLS alert 42.", runtime.TlsState.FatalAlertDescription);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProhibitedKeyUpdateViolationsAreConvertedIntoConnectionCloseLifecycleTransitions()
    {
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePath();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.ProhibitedKeyUpdateViolation)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState?.Origin);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TerminalState?.Close.TransportErrorCode);
        Assert.Equal(QuicTransportErrorCode.KeyUpdateError, runtime.TlsState.FatalAlertCode);
        Assert.Equal("TLS KeyUpdate was prohibited.", runtime.TlsState.FatalAlertDescription);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionNotifyStreamsOfTerminalStateEffect);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePath()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 0,
                new QuicConnectionPathIdentity("203.0.113.10", RemotePort: 443),
                new byte[1200]),
            nowTicks: 0);

        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        return runtime;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
