namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP1-0004">An endpoint MAY retain state for a packet after it is declared lost for a limited time to allow for packet reordering.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP1-0004")]
public sealed class REQ_QUIC_RFC9002_SAP1_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotCollapseWhenAReorderedAckFallsInsideTheLossWindow()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 5_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: true, lost: false),
                new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(9_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDetectPersistentCongestion_StillRetainsReorderedStateAtTheDurationBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 7_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: true, lost: false),
                new(QuicPacketNumberSpace.ApplicationData, 8_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.False(persistentCongestionDetected);
        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(8_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }
}
