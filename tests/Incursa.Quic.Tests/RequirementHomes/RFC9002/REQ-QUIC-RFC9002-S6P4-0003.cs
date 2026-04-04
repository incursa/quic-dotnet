namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P4-0003")]
public sealed class REQ_QUIC_RFC9002_S6P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDetectPersistentCongestion_DiscardsInFlightZeroRttPacketsWhenTheyAreRejected()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    2_000,
                    1_200,
                    ackEliciting: true,
                    inFlight: true,
                    acknowledged: false,
                    lost: true),
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    9_000,
                    1_200,
                    ackEliciting: true,
                    inFlight: true,
                    acknowledged: false,
                    lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(9_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotDiscardRejectedZeroRttPacketsWhenTheyWereNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    500,
                    1_200,
                    ackEliciting: true,
                    inFlight: false,
                    acknowledged: false,
                    lost: true),
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    700,
                    1_200,
                    ackEliciting: true,
                    inFlight: false,
                    acknowledged: false,
                    lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.False(persistentCongestionDetected);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
    }
}
