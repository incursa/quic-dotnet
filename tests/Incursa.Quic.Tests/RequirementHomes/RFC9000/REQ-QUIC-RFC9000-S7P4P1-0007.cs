namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0007")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NonZeroBidirectionalAllowancePermitsClientApplicationDataForZeroRtt()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 1,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamsBidi = 1,
        };

        Assert.True(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroConnectionDataAllowanceDoesNotPermitClientApplicationDataForZeroRtt()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 0,
            InitialMaxStreamDataBidiRemote = 1,
            InitialMaxStreamsBidi = 1,
        };

        Assert.False(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void OnlyServerInitiatedBidirectionalCreditDoesNotPermitClientApplicationDataForZeroRtt()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 1,
            InitialMaxStreamDataBidiLocal = 1,
            InitialMaxStreamsBidi = 1,
        };

        Assert.False(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(parameters));
    }
}
