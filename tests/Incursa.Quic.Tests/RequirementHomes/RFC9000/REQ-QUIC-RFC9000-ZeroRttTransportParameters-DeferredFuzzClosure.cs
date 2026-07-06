// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ZeroRttTransportParameters_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0348")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ClientApplicationDataAllowanceFuzz_RequiresNonZeroConnectionAndStreamCredit()
    {
        for (ulong value = 0; value <= 4; value++)
        {
            QuicTransportParameters bidirectional = new()
            {
                InitialMaxData = value,
                InitialMaxStreamDataBidiRemote = value,
                InitialMaxStreamsBidi = value,
            };
            QuicTransportParameters unidirectional = new()
            {
                InitialMaxData = value,
                InitialMaxStreamDataUni = value,
                InitialMaxStreamsUni = value,
            };
            QuicTransportParameters serverOnly = new()
            {
                InitialMaxData = value,
                InitialMaxStreamDataBidiLocal = value,
                InitialMaxStreamsBidi = value,
            };

            bool expectedApplicationDataAllowed = value > 0;
            Assert.Equal(
                expectedApplicationDataAllowed,
                QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(bidirectional));
            Assert.Equal(
                expectedApplicationDataAllowed,
                QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(unidirectional));
            Assert.False(QuicZeroRttTransportParameterPolicy.HasNonZeroClientApplicationDataAllowance(serverOnly));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0350")]
    [Requirement("REQ-QUIC-RFC9000-0351")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ServerZeroRttAcceptanceFuzz_RejectsUnsupportedOrReducedRememberedParameters()
    {
        string[] optionalParameters =
        [
            "max_idle_timeout",
            "max_udp_payload_size",
            "disable_active_migration",
        ];

        foreach (string parameterName in optionalParameters)
        {
            QuicZeroRttTransportParameterAcceptanceDecision decision =
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                    configureCurrent: current => ReduceOptionalParameter(current, parameterName));

            Assert.False(decision.CanAccept);
            Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedOptionalValue, decision.Failure);
            Assert.Equal(parameterName, decision.ParameterName);
        }

        string[] requiredParameters =
        [
            "active_connection_id_limit",
            "initial_max_data",
            "initial_max_stream_data_bidi_local",
            "initial_max_stream_data_bidi_remote",
            "initial_max_stream_data_uni",
            "initial_max_streams_bidi",
            "initial_max_streams_uni",
        ];

        foreach (string parameterName in requiredParameters)
        {
            QuicZeroRttTransportParameterAcceptanceDecision decision =
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate(
                    configureCurrent: current => ReduceRequiredParameter(current, parameterName));

            Assert.False(decision.CanAccept);
            Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.ReducedRequiredLimit, decision.Failure);
            Assert.Equal(parameterName, decision.ParameterName);
        }

        QuicZeroRttTransportParameterAcceptanceDecision accepted =
            QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.Evaluate();
        Assert.True(accepted.CanAccept);

        QuicZeroRttTransportParameterAcceptanceDecision missing =
            QuicZeroRttTransportParameterPolicy.EvaluateServerZeroRttAcceptance(
                QuicS7P4P1ZeroRttTransportParameterPolicyTestSupport.CreateRememberedParameters(),
                currentServerTransportParameters: null);
        Assert.False(missing.CanAccept);
        Assert.Equal(QuicZeroRttTransportParameterAcceptanceFailure.MissingCurrentParameters, missing.Failure);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0353")]
    [Requirement("REQ-QUIC-RFC9000-0356")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ZeroRttTransportParameterUseFuzz_OnlyRememberedValuesAreUsableInZeroRtt()
    {
        foreach (QuicZeroRttTransportParameterValueSource source in Enum.GetValues<QuicZeroRttTransportParameterValueSource>())
        {
            QuicZeroRttTransportParameterUseDecision zeroRtt =
                QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                    QuicTlsEncryptionLevel.ZeroRtt,
                    source);
            QuicTransportErrorCode? serverError =
                QuicZeroRttTransportParameterPolicy.GetServerZeroRttTransportParameterUseError(source);

            if (source == QuicZeroRttTransportParameterValueSource.Remembered)
            {
                Assert.True(zeroRtt.CanUse);
                Assert.Equal(QuicZeroRttTransportParameterUseFailure.None, zeroRtt.Failure);
                Assert.Null(zeroRtt.ErrorCode);
                Assert.Null(serverError);
            }
            else if (source == QuicZeroRttTransportParameterValueSource.Unknown)
            {
                Assert.False(zeroRtt.CanUse);
                Assert.Equal(QuicZeroRttTransportParameterUseFailure.MissingRememberedValue, zeroRtt.Failure);
                Assert.Null(zeroRtt.ErrorCode);
                Assert.Null(serverError);
            }
            else
            {
                Assert.False(zeroRtt.CanUse);
                Assert.Equal(QuicTransportErrorCode.ProtocolViolation, zeroRtt.ErrorCode);
                Assert.Equal(QuicTransportErrorCode.ProtocolViolation, serverError);
            }
        }

        foreach (QuicZeroRttTransportParameterValueSource source in new[]
        {
            QuicZeroRttTransportParameterValueSource.UpdatedFromHandshake,
            QuicZeroRttTransportParameterValueSource.UpdatedFromOneRttFrame,
        })
        {
            QuicZeroRttTransportParameterUseDecision oneRtt =
                QuicZeroRttTransportParameterPolicy.EvaluateClientTransportParameterUseForPacket(
                    QuicTlsEncryptionLevel.OneRtt,
                    source);

            Assert.True(oneRtt.CanUse);
        }
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
            case "max_datagram_frame_size":
                parameters.MaxDatagramFrameSize = 0;
                break;
            case "disable_active_migration":
                parameters.DisableActiveMigration = false;
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(parameterName), parameterName, "Unknown parameter.");
        }
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
