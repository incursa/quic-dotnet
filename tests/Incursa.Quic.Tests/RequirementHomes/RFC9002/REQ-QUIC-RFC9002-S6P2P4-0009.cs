namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S6P2P4-0009">Instead of sending an ack-eliciting packet, the sender MAY mark any packets still in flight as lost.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S6P2P4-0009")]
public sealed class REQ_QUIC_RFC9002_S6P2P4_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_AllowsMarkingAnInFlightPacketLostInsteadOfSendingAnotherProbe()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(1_200);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.True(state.HasRecoveryStartTime);
        Assert.Equal(2_000UL, state.RecoveryStartTimeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryRegisterLoss_RejectsPacketsThatAreNotInFlightWhenNoAckOnlyLossSignalIsAllowed()
    {
        QuicCongestionControlState state = new();

        Assert.False(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 2_000,
            packetInFlight: false,
            allowAckOnlyLossSignal: false));
    }
}
