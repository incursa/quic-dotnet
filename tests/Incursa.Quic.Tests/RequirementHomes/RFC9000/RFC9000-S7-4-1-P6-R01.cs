// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-4-1-P6-R01")]
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

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ServerZeroRttAcceptanceFuzz_AcceptsOnlyNonReducedClientUsableValues()
    {
        for (ulong rememberedInitialMaxData = 1_000; rememberedInitialMaxData <= 1_004; rememberedInitialMaxData++)
        {
            QuicZeroRttTransportParameterAcceptanceDecision equalDecision =
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                    configureRemembered: remembered => remembered.InitialMaxData = rememberedInitialMaxData,
                    configureCurrent: current => current.InitialMaxData = rememberedInitialMaxData);
            QuicZeroRttTransportParameterAcceptanceDecision increasedDecision =
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                    configureRemembered: remembered => remembered.InitialMaxData = rememberedInitialMaxData,
                    configureCurrent: current => current.InitialMaxData = rememberedInitialMaxData + 1);
            QuicZeroRttTransportParameterAcceptanceDecision reducedDecision =
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                    configureRemembered: remembered => remembered.InitialMaxData = rememberedInitialMaxData,
                    configureCurrent: current => current.InitialMaxData = rememberedInitialMaxData - 1);

            Assert.True(equalDecision.CanAccept);
            Assert.True(increasedDecision.CanAccept);
            Assert.False(reducedDecision.CanAccept);
            Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit, reducedDecision.Failure);
            Assert.Equal("initial_max_data", reducedDecision.ParameterName);
        }
    }
}
