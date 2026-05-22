namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0348")]
public sealed class REQ_QUIC_RFC9000_0348
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
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
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
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
    [Requirement("REQ-QUIC-RFC9000-S5-0004")]
    [Requirement("REQ-QUIC-RFC9000-S5-0005")]
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
