namespace Incursa.Quic.Tests;

public sealed class QuicIdleTimeoutStateTests
{
    [Theory]
    [InlineData(25UL, null, 5UL, true, 25UL)]
    [InlineData(0UL, 40UL, 5UL, true, 40UL)]
    [InlineData(25UL, 40UL, 5UL, true, 25UL)]
    [InlineData(4UL, 10UL, 2UL, true, 6UL)]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0001")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0007")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Trait("Category", "Positive")]
    public void TryComputeEffectiveIdleTimeoutMicros_UsesTheMinimumAdvertisedValueAndThePtoFloor(
        ulong? localMaxIdleTimeoutMicros,
        ulong? peerMaxIdleTimeoutMicros,
        ulong currentProbeTimeoutMicros,
        bool expectedComputed,
        ulong expectedEffectiveIdleTimeoutMicros)
    {
        Assert.Equal(expectedComputed, QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros,
            peerMaxIdleTimeoutMicros,
            currentProbeTimeoutMicros,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(expectedEffectiveIdleTimeoutMicros, effectiveIdleTimeoutMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0003")]
    [Trait("Category", "Negative")]
    public void TryComputeEffectiveIdleTimeoutMicros_ReturnsFalseWhenNeitherEndpointAdvertisesAnIdleTimeout()
    {
        Assert.False(QuicIdleTimeoutState.TryComputeEffectiveIdleTimeoutMicros(
            localMaxIdleTimeoutMicros: null,
            peerMaxIdleTimeoutMicros: null,
            currentProbeTimeoutMicros: 5,
            out ulong effectiveIdleTimeoutMicros));

        Assert.Equal(0UL, effectiveIdleTimeoutMicros);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0005")]
    [Requirement("REQ-QUIC-RFC9000-S10P1-0006")]
    [Trait("Category", "Positive")]
    public void RecordPeerPacketProcessedAndRecordAckElicitingPacketSent_RestartTheTimerAtTheRightTimes()
    {
        QuicIdleTimeoutState state = new(100);

        Assert.Equal(0UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(100UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(state.HasTimedOut(100));
        Assert.True(state.HasTimedOut(101));

        state.RecordAckElicitingPacketSent(20);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
        Assert.False(state.HasTimedOut(120));
        Assert.True(state.HasTimedOut(121));

        state.RecordAckElicitingPacketSent(30);

        Assert.Equal(20UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(120UL, state.IdleTimeoutDeadlineMicros);

        state.RecordPeerPacketProcessed(40);

        Assert.Equal(40UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(140UL, state.IdleTimeoutDeadlineMicros);
        Assert.False(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);

        state.RecordAckElicitingPacketSent(60);

        Assert.Equal(60UL, state.IdleTimerRestartAtMicros);
        Assert.Equal(160UL, state.IdleTimeoutDeadlineMicros);
        Assert.True(state.HasAckElicitingPacketBeenSentSinceLastPeerPacket);
    }
}
