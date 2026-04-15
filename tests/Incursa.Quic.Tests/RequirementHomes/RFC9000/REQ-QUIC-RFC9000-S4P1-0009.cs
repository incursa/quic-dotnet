namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S4P1-0009">A receiver MAY advertise a larger limit for a connection by sending a MAX_DATA frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
public sealed class REQ_QUIC_RFC9000_S4P1_0009
{
    private const ulong MaximumFlowControlLimit = 0x3FFF_FFFF_FFFF_FFFFUL;

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxDataFrame_AdvertisesLargerConnectionLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionSendLimit: 8);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(12)));
        Assert.Equal(12UL, state.ConnectionSendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxDataFrame_IgnoresSmallerConnectionLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionSendLimit: 8);

        Assert.False(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(7)));
        Assert.Equal(8UL, state.ConnectionSendLimit);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxDataFrame_AcceptsTheMaximumRepresentableConnectionLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionSendLimit: 0);

        Assert.True(state.TryApplyMaxDataFrame(new QuicMaxDataFrame(MaximumFlowControlLimit)));
        Assert.Equal(MaximumFlowControlLimit, state.ConnectionSendLimit);
    }
}
