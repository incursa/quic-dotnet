namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0001">A sender SHOULD pace sending of all in-flight packets based on input from the congestion controller.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P7-0001")]
public sealed class REQ_QUIC_RFC9002_S7P7_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputePacingIntervalMicros_ComputesThePacingIntervalForInFlightPackets()
    {
        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: false,
            out ulong pacingIntervalMicros));

        Assert.Equal(100UL, pacingIntervalMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    [Requirement("REQ-QUIC-RFC9002-S7-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0001")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0002")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0003")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0004")]
    [Requirement("REQ-QUIC-RFC9002-S7P7-0005")]
    public void TryComputePacingIntervalAndBurstLimit_HonorThePacingAndBurstHelpers()
    {
        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: false,
            out ulong pacingIntervalMicros));
        Assert.Equal(100UL, pacingIntervalMicros);

        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: true,
            out ulong ackOnlyIntervalMicros));
        Assert.Equal(0UL, ackOnlyIntervalMicros);

        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: false,
            out ulong cappedBurstBytes));
        Assert.Equal(12_000UL, cappedBurstBytes);

        Assert.True(QuicCongestionControlState.TryGetBurstLimitBytes(
            initialCongestionWindowBytes: 12_000,
            pathCanAbsorbLargerBursts: true,
            out ulong expandedBurstBytes,
            largerBurstLimitBytes: 24_000));
        Assert.Equal(24_000UL, expandedBurstBytes);

        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: false));
        Assert.Equal(12_000UL, state.CongestionWindowBytes);

        state = new QuicCongestionControlState();
        state.RegisterPacketSent(1_200);
        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            pacingLimited: true));
        Assert.Equal(13_200UL, state.CongestionWindowBytes);
    }
}
