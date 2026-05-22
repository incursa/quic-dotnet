namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0350")]
public sealed class REQ_QUIC_RFC9000_0350
{
    [Theory]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("max_idle_timeout")]
    [InlineData("max_udp_payload_size")]
    [InlineData("disable_active_migration")]
    public void ServerZeroRttAcceptanceRejectsReducedRememberedOptionalParameter(string parameterName)
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                configureCurrent: current => ReduceOptionalParameter(current, parameterName));

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue, decision.Failure);
        Assert.Equal(parameterName, decision.ParameterName);
    }

    private static void ReduceOptionalParameter(QuicTransportParameters parameters, string parameterName)
    {
        switch (parameterName)
        {
            case "max_idle_timeout":
                parameters.MaxIdleTimeout = 29;
                break;
            case "max_udp_payload_size":
                parameters.MaxUdpPayloadSize = 1_299;
                break;
            case "disable_active_migration":
                parameters.DisableActiveMigration = false;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(parameterName), parameterName, "Unknown parameter.");
        }
    }
}
