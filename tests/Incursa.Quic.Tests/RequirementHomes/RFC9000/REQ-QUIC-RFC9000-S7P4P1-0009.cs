namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0009")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttAcceptanceAllowsRestoredValuesThatCurrentServerParametersCanSupport()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate();

        Assert.True(decision.CanAccept);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerZeroRttAcceptanceRejectsWhenCurrentServerParametersAreUnavailable()
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.CreateRememberedParameters(),
                currentServerTransportParameters: null);

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.MissingCurrentParameters, decision.Failure);
        Assert.Equal("current_server_transport_parameters", decision.ParameterName);
    }
}
