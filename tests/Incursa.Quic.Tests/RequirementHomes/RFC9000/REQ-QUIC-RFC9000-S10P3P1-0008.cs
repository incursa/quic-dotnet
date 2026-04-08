namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P1-0008">If the last 16 bytes of the datagram are identical in value to a stateless reset token, the endpoint MUST enter the draining period and not send any further packets on this connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P1-0008")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryHandlePotentialStatelessReset_EntersDrainingAndStopsSendingOnMatchingToken()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x60);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryHandlePotentialStatelessReset(datagram, statelessResetToken));
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryHandlePotentialStatelessReset_LeavesTheConnectionSendableWhenTheTokenDoesNotMatch()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x60);
        byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(0x80);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();

        Assert.False(state.TryHandlePotentialStatelessReset(datagram, nonMatchingToken));
        Assert.False(state.IsDraining);
        Assert.True(state.CanSendPackets);
    }
}
