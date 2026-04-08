namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-INT-0003")]
public sealed class REQ_QUIC_INT_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TlsTransportStateTracksParametersKeysAndHandshakeConfirmation()
    {
        QuicTransportParameters localParameters = new()
        {
            MaxIdleTimeout = 15,
        };

        QuicTransportParameters peerParameters = new()
        {
            DisableActiveMigration = true,
        };

        QuicTlsTransportState state = new();

        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.LocalTransportParametersReady,
            TransportParameters: localParameters)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.PeerTransportParametersAuthenticated,
            TransportParameters: peerParameters)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Initial)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysAvailable,
            QuicTlsEncryptionLevel.Handshake)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeyUpdateInstalled,
            KeyPhase: 2)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(
            QuicTlsUpdateKind.KeysDiscarded,
            QuicTlsEncryptionLevel.Initial)));
        Assert.True(state.TryApply(new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)));

        Assert.Same(localParameters, state.LocalTransportParameters);
        Assert.Same(peerParameters, state.PeerTransportParameters);
        Assert.True(state.InitialKeysAvailable);
        Assert.True(state.HandshakeKeysAvailable);
        Assert.True(state.OneRttKeysAvailable);
        Assert.True(state.InitialKeysDiscarded);
        Assert.True(state.HandshakeConfirmed);
        Assert.Equal(2U, state.CurrentOneRttKeyPhase);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeConsumesTlsHandshakeConfirmedUpdates()
    {
        FakeMonotonicClock clock = new(0);
        QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState(), clock);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(QuicTlsUpdateKind.HandshakeConfirmed)),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionEventKind.TlsStateUpdated, result.EventKind);
        Assert.True(runtime.TlsState.HandshakeConfirmed);
        Assert.True(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
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
