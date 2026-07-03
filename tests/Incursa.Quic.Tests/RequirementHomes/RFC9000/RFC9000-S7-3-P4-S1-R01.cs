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
}
