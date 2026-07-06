// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S7-3-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_S7P3_0007
{
    [Theory]
    [MemberData(nameof(QuicTransportParameterTestData.MissingConnectionIdBindingCases), MemberType = typeof(QuicTransportParameterTestData))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S7-3-P4-S1-R01">An endpoint MUST treat the absence of the initial_source_connection_id transport parameter from either endpoint or the absence of the original_destination_connection_id transport parameter from the server as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S7-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryValidateConnectionIdBindings_RejectsMissingConnectionIdBindings(
        object receiverRoleValue,
        byte[] initialDestinationConnectionId,
        byte[] initialSourceConnectionId,
        bool usedRetry,
        byte[] retrySourceConnectionId,
        object peerParametersValue,
        object expectedErrorValue)
    {
        QuicTransportParameterRole receiverRole = (QuicTransportParameterRole)receiverRoleValue;
        QuicTransportParameters peerParameters = (QuicTransportParameters)peerParametersValue;
        QuicConnectionIdBindingValidationError expectedError = (QuicConnectionIdBindingValidationError)expectedErrorValue;

        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            receiverRole,
            initialDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry,
            retrySourceConnectionId,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(expectedError, validationError);
    }

    [Fact]
    [Requirement("RFC9000-S7-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryValidateConnectionIdBindings_AcceptsWhenRequiredConnectionIdBindingsArePresent()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
        };

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
            usedRetry: false,
            ReadOnlySpan<byte>.Empty,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }

    [Fact]
    [Requirement("RFC9000-S7-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryValidateConnectionIdBindingsFuzz_RejectsMissingRequiredConnectionIdBindings()
    {
        (QuicTransportParameterRole ReceiverRole, byte[] InitialDestinationConnectionId, byte[] InitialSourceConnectionId, bool UsedRetry, byte[] RetrySourceConnectionId, QuicTransportParameters PeerParameters, QuicConnectionIdBindingValidationError ExpectedError)[] cases =
        [
            (
                QuicTransportParameterRole.Client,
                [0x10, 0x11],
                [0x20, 0x21],
                false,
                [],
                new QuicTransportParameters { InitialSourceConnectionId = [0x20, 0x21] },
                QuicConnectionIdBindingValidationError.MissingOriginalDestinationConnectionId),
            (
                QuicTransportParameterRole.Client,
                [0x12, 0x13],
                [0x22, 0x23],
                false,
                [],
                new QuicTransportParameters { OriginalDestinationConnectionId = [0x12, 0x13] },
                QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId),
            (
                QuicTransportParameterRole.Client,
                [0x14, 0x15],
                [0x24, 0x25],
                true,
                [0x34, 0x35],
                new QuicTransportParameters
                {
                    OriginalDestinationConnectionId = [0x14, 0x15],
                    InitialSourceConnectionId = [0x24, 0x25],
                },
                QuicConnectionIdBindingValidationError.MissingRetrySourceConnectionId),
            (
                QuicTransportParameterRole.Server,
                [],
                [0x26, 0x27],
                false,
                [],
                new QuicTransportParameters(),
                QuicConnectionIdBindingValidationError.MissingInitialSourceConnectionId),
        ];

        foreach ((QuicTransportParameterRole receiverRole,
                     byte[] initialDestinationConnectionId,
                     byte[] initialSourceConnectionId,
                     bool usedRetry,
                     byte[] retrySourceConnectionId,
                     QuicTransportParameters peerParameters,
                     QuicConnectionIdBindingValidationError expectedError) in cases)
        {
            Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
                receiverRole,
                initialDestinationConnectionId,
                initialSourceConnectionId,
                usedRetry,
                retrySourceConnectionId,
                peerParameters,
                out QuicConnectionIdBindingValidationError validationError));
            Assert.Equal(expectedError, validationError);
        }
    }
}
