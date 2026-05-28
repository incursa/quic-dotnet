// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0351")]
public sealed class REQ_QUIC_RFC9000_0351
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
