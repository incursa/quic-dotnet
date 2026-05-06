namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0005")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttAcceptanceAllowsCurrentValuesThatPreserveRememberedClientUsableValues()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate();

        Assert.True(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.None, decision.Failure);
        Assert.Null(decision.ParameterName);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerZeroRttAcceptanceRejectsReducedLimitThatClientDataCouldViolate()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                configureCurrent: current => current.InitialMaxData = 999);

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit, decision.Failure);
        Assert.Equal("initial_max_data", decision.ParameterName);
    }
}
