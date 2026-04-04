namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P7-0005">Packets containing only ACK frames SHOULD therefore not be paced.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P7-0005")]
public sealed class REQ_QUIC_RFC9002_S7P7_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryComputePacingIntervalMicros_DoesNotPaceAckOnlyPackets()
    {
        Assert.True(QuicCongestionControlState.TryComputePacingIntervalMicros(
            congestionWindowBytes: 10_000,
            smoothedRttMicros: 1_000,
            packetSizeBytes: 1_250,
            ackOnlyPacket: true,
            out ulong pacingIntervalMicros));

        Assert.Equal(0UL, pacingIntervalMicros);
    }
}
