namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP11-0002">When Initial or Handshake keys are discarded, the sender MUST remove the discarded packets from bytes in flight and clear `sent_packets` for that packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP11-0002")]
public sealed class REQ_QUIC_RFC9002_SAP11_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryDetectPersistentCongestion_RemovesDiscardedInitialAndHandshakePacketsFromCongestionAccounting()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 9_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
        Assert.Equal(9_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryDetectPersistentCongestion_DoesNotChangeCongestionAccountingForPacketsThatWereNotInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 500, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 700, 1_200, ackEliciting: true, inFlight: false, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.False(persistentCongestionDetected);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryDetectPersistentCongestion_RemovesPacketsAtTheDiscardDurationBoundary()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);

        Assert.True(state.TryDetectPersistentCongestion(
            [
                new(QuicPacketNumberSpace.Initial, 2_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
                new(QuicPacketNumberSpace.Handshake, 8_000, 1_200, ackEliciting: true, inFlight: true, acknowledged: false, lost: true),
            ],
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected,
            applyReset: false));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
        Assert.Equal(8_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
    }
}
