namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP9-0001")]
public sealed class REQ_QUIC_RFC9002_SBP9_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDetectPersistentCongestion_RemovesInitialPacketsFromBytesInFlightWhenKeysAreDiscarded()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 500, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotRemoveInitialPacketsThatWereNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 500, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDetectPersistentCongestion_RemovesHandshakePacketsAtTheFirstRttSampleBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Handshake, 1_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
    }
}
