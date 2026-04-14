namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S7P6P2-0001")]
public sealed class REQ_QUIC_RFC9002_S7P6P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P1-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P6-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P6P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryDetectPersistentCongestion_RequiresAckElicitingLossesAcrossTheWindow()
    {
        QuicCongestionControlState failingState = new();
        QuicPersistentCongestionPacket[] failingPackets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.Handshake, 5_000, 1_200, true, true, acknowledged: true, lost: false),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(failingState.TryDetectPersistentCongestion(
            failingPackets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool failingPersistentCongestionDetected));
        Assert.False(failingPersistentCongestionDetected);
        Assert.Equal(6_000UL, failingState.CongestionWindowBytes);
        Assert.True(failingState.HasRecoveryStartTime);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        QuicPersistentCongestionPacket[] packets =
        [
            new(QuicPacketNumberSpace.Initial, 2_000, 1_200, true, true, acknowledged: false, lost: true),
            new(QuicPacketNumberSpace.ApplicationData, 9_000, 1_200, true, true, acknowledged: false, lost: true),
        ];

        Assert.True(state.TryDetectPersistentCongestion(
            packets,
            firstRttSampleMicros: 1_000,
            smoothedRttMicros: 1_000,
            rttVarMicros: 0,
            maxAckDelayMicros: 0,
            out bool persistentCongestionDetected));

        Assert.True(persistentCongestionDetected);
        Assert.Equal(state.MinimumCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(ulong.MaxValue, state.SlowStartThresholdBytes);
        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(9_600UL, state.BytesInFlightBytes);
    }
}
