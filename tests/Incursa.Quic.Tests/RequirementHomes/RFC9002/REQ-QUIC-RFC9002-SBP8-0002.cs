namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-SBP8-0002")]
public sealed class REQ_QUIC_RFC9002_SBP8_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDetectPersistentCongestion_UsesTheLatestLostPacketSendTimeWhenItStartsRecovery()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(9_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotEnterRecoveryWhenLossesAreNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.ApplicationData, 6_000, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDetectPersistentCongestion_UsesTheLatestLossTimeAtTheCollapseBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.ApplicationData, 8_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(8_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }
}
