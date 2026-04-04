namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0006">An endpoint MUST NOT send a packet if it would cause bytes_in_flight to be larger than the congestion window, unless the packet is sent on a PTO timer expiration or when entering recovery.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7-0006")]
public sealed class REQ_QUIC_RFC9002_S7_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void CanSend_RejectsCongestionControlledPacketsThatWouldExceedTheWindow()
    {
        QuicCongestionControlState state = new();
        state.RegisterPacketSent(state.CongestionWindowBytes);

        Assert.False(state.CanSend(1, isAckOnlyPacket: false, isProbePacket: false));
    }
}
