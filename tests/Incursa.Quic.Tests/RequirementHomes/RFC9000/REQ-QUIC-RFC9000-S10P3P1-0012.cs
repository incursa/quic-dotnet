namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S10P3P1-0012">If the last 16 bytes of the datagram are identical in value to a stateless reset token, the endpoint MUST NOT send any further packets on this connection.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S10P3P1-0012")]
public sealed class REQ_QUIC_RFC9000_S10P3P1_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryHandlePotentialStatelessReset_DisablesSendingOnAMatchingToken()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x70);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryHandlePotentialStatelessReset(datagram, statelessResetToken));
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryHandlePotentialStatelessReset_StaysNonSendableAfterARepeatedMatch()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x70);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();

        Assert.True(state.TryHandlePotentialStatelessReset(datagram, statelessResetToken));
        Assert.False(state.TryHandlePotentialStatelessReset(datagram, statelessResetToken));
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryHandlePotentialStatelessReset_KeepsSendingEnabledWhenTheTokenDoesNotMatch()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x70);
        byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(0x90);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();

        Assert.False(state.TryHandlePotentialStatelessReset(datagram, nonMatchingToken));
        Assert.True(state.CanSendPackets);
        Assert.False(state.IsDraining);
    }
}
