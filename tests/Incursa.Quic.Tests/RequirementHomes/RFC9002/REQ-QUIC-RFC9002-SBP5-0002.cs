namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SBP5-0002">On packet acknowledgment, the sender MUST subtract the packet&apos;s sent_bytes from bytes_in_flight.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SBP5-0002")]
public sealed class REQ_QUIC_RFC9002_SBP5_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterAcknowledgedPacket_SubtractsAckedBytesFromBytesInFlight()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterAcknowledgedPacket(
            sentBytes: 1_200,
            sentAtMicros: 1_000,
            packetInFlight: true,
            applicationLimited: true));

        Assert.Equal(12_000UL, state.BytesInFlightBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }
}
