namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P1-0006">An endpoint that continues to receive data for a terminated connection MUST attempt the stateless reset process.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P1-0006")]
public sealed class REQ_QUIC_RFC9000_S11P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClosingLifecycleStateTransitionsToDrainingWhenAStatelessResetTokenMatches()
    {
        byte[] statelessResetToken =
        [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F,
        ];

        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();
        Assert.True(state.TryEnterClosingState());

        Assert.True(state.TryHandlePotentialStatelessReset(datagram, statelessResetToken));
        Assert.True(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ClosingLifecycleStateDoesNotEnterDrainingWhenTheTokenDoesNotMatch()
    {
        byte[] statelessResetToken = QuicStatelessResetRequirementTestData.CreateToken(0x30);
        byte[] nonMatchingToken = QuicStatelessResetRequirementTestData.CreateToken(0x50);
        byte[] datagram = QuicStatelessResetRequirementTestData.FormatDatagram(statelessResetToken);

        QuicConnectionLifecycleState state = new();
        Assert.True(state.TryEnterClosingState());

        Assert.False(state.TryHandlePotentialStatelessReset(datagram, nonMatchingToken));
        Assert.True(state.IsClosing);
        Assert.False(state.IsDraining);
        Assert.False(state.CanSendPackets);
    }
}
