namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0002">The largest UDP payload an endpoint sends at any given time is referred to as the endpoint's maximum datagram size.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0002")]
public sealed class REQ_QUIC_RFC9000_S14P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConstructorAndUpdate_TrackTheCurrentMaximumDatagramSize()
    {
        QuicCongestionControlState state = new();

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, state.MaxDatagramSizeBytes);

        state.UpdateMaxDatagramSize(1350, resetToInitialWindow: false);

        Assert.Equal(1350UL, state.MaxDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Constructor_RejectsZeroMaximumDatagramSizes()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicCongestionControlState(0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void Constructor_AllowsTheRFCMinimumMaximumDatagramSize()
    {
        QuicCongestionControlState state = new(QuicVersionNegotiation.Version1MinimumDatagramPayloadSize);

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, state.MaxDatagramSizeBytes);
    }
}
