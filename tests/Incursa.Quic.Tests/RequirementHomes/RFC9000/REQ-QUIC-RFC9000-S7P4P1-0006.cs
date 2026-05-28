// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P4P1-0006")]
public sealed class REQ_QUIC_RFC9000_S7P4P1_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerZeroRttAcceptanceAllowsEqualRememberedSection18P2Limits()
    {
        QuicTransportParameters remembered =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.CreateRememberedParameters();

        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                remembered,
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.CreateRememberedParameters());

        Assert.True(decision.CanAccept);
    }

    [Theory]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    [InlineData("active_connection_id_limit")]
    [InlineData("initial_max_data")]
    [InlineData("initial_max_stream_data_bidi_local")]
    [InlineData("initial_max_stream_data_bidi_remote")]
    [InlineData("initial_max_stream_data_uni")]
    [InlineData("initial_max_streams_bidi")]
    [InlineData("initial_max_streams_uni")]
    public void ServerZeroRttAcceptanceRejectsReducedRememberedSection18P2Limit(string parameterName)
    {
        QuicZeroRttTransportParameterAcceptanceDecision decision =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                configureCurrent: current => ReduceRequiredParameter(current, parameterName));

        Assert.False(decision.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit, decision.Failure);
        Assert.Equal(parameterName, decision.ParameterName);
    }

    private static void ReduceRequiredParameter(QuicTransportParameters parameters, string parameterName)
    {
        switch (parameterName)
        {
            case "active_connection_id_limit":
                parameters.ActiveConnectionIdLimit = 3;
                break;
            case "initial_max_data":
                parameters.InitialMaxData = 999;
                break;
            case "initial_max_stream_data_bidi_local":
                parameters.InitialMaxStreamDataBidiLocal = 99;
                break;
            case "initial_max_stream_data_bidi_remote":
                parameters.InitialMaxStreamDataBidiRemote = 119;
                break;
            case "initial_max_stream_data_uni":
                parameters.InitialMaxStreamDataUni = 79;
                break;
            case "initial_max_streams_bidi":
                parameters.InitialMaxStreamsBidi = 1;
                break;
            case "initial_max_streams_uni":
                parameters.InitialMaxStreamsUni = 2;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(parameterName), parameterName, "Unknown parameter.");
        }
    }
}
