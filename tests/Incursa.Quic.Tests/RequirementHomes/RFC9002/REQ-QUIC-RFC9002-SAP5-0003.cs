namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-SAP5-0003">When a sent packet is in flight, the sender MUST account for `sent_bytes` in congestion control and set the loss detection timer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-SAP5-0003")]
public sealed class REQ_QUIC_RFC9002_SAP5_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicCongestionControlState_AccountsInFlightBytesAndRestartsPtoOnAckElicitingSend()
    {
        QuicCongestionControlState state = new();

        Assert.Equal(0UL, state.BytesInFlightBytes);

        state.RegisterPacketSent(1_200);

        Assert.Equal(1_200UL, state.BytesInFlightBytes);
        Assert.Equal(0, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(
            ptoCount: 3,
            ackElicitingPacketSent: true));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void QuicCongestionControlState_DoesNotCountAckOnlyPacketsOrRestartPtoWithoutASend()
    {
        QuicCongestionControlState state = new();

        state.RegisterPacketSent(1_200, isAckOnlyPacket: true);

        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.Equal(3, QuicRecoveryTiming.ResetProbeTimeoutBackoffCount(ptoCount: 3));
    }
}
