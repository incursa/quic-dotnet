namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S2-0004")]
public sealed class REQ_QUIC_RFC9002_S2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryDetectPersistentCongestion_RemovesLostAckElicitingPacketsThatWereInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    sentAtMicros: 2_000,
                    sentBytes: 1_200,
                    ackEliciting: true,
                    inFlight: true,
                    acknowledged: false,
                    lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryDetectPersistentCongestion_DoesNotRemoveLostPacketsThatWereNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    sentAtMicros: 2_000,
                    sentBytes: 1_200,
                    ackEliciting: true,
                    inFlight: false,
                    acknowledged: false,
                    lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryDetectPersistentCongestion_TreatsNonAckElicitingInFlightPacketsAsInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(
                    QuicPacketNumberSpace.ApplicationData,
                    sentAtMicros: 2_000,
                    sentBytes: 1_200,
                    ackEliciting: false,
                    inFlight: true,
                    acknowledged: false,
                    lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(10_800UL, state.BytesInFlightBytes);
    }
}
