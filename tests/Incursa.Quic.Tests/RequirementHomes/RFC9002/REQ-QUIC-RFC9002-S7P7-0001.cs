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
}
