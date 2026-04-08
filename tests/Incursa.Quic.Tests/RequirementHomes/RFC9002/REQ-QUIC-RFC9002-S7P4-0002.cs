namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P4-0002">Endpoints MUST NOT ignore the loss of packets that were sent after the earliest acknowledged packet in a given packet number space.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P4-0002")]
public sealed class REQ_QUIC_RFC9002_S7P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryRegisterLoss_DoesNotIgnorePacketsSentAfterTheEarliestAcknowledgedPacket()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true,
            packetCanBeDecrypted: true,
            keysAvailable: true,
            sentAfterEarliestAcknowledgedPacket: true));

        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
        Assert.Equal(6_000UL, state.CongestionWindowBytes);
        Assert.Equal(12_000UL, state.BytesInFlightBytes);
    }
}
