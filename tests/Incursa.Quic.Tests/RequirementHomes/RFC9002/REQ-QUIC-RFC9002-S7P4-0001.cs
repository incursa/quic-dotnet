namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7P4-0001">Endpoints MAY ignore the loss of Handshake, 0-RTT, and 1-RTT packets that might have arrived before the peer had packet protection keys to process those packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7P4-0001")]
public sealed class REQ_QUIC_RFC9002_S7P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryRegisterLoss_IgnoresPacketsThatMayHaveArrivedBeforeKeysWereAvailable()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(12_000);
        state.RegisterPacketSent(1_200, isProbePacket: true);

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 100,
            packetInFlight: true,
            packetCanBeDecrypted: false,
            keysAvailable: false,
            sentAfterEarliestAcknowledgedPacket: false));

        Assert.False(state.HasRecoveryStartTime);
        Assert.Equal(13_200UL, state.BytesInFlightBytes);
        Assert.Equal(12_000UL, state.CongestionWindowBytes);
    }
}
