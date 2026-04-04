namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S2-0004">Packets MUST be considered in flight when they are ack-eliciting or contain a PADDING frame and have been sent but are not yet acknowledged, declared lost, or discarded along with old keys.</workbench-requirement>
/// </workbench-requirements>
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
