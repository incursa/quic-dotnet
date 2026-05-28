// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
public sealed class REQ_QUIC_RFC9000_S7P3_0005
{
    [Theory]
    [MemberData(nameof(QuicTransportParameterTestData.MatchingConnectionIdBindingCases), MemberType = typeof(QuicTransportParameterTestData))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0005">The values provided by a peer for these transport parameters MUST match the values that an endpoint used in the Destination and Source Connection ID fields of Initial packets that it sent (and received, for servers).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0326">Endpoints MUST validate that received transport parameters match received connection ID values.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-0326")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryValidateConnectionIdBindings_AcceptsMatchingConnectionIdBindings(
        object receiverRoleValue,
        byte[] initialDestinationConnectionId,
        byte[] initialSourceConnectionId,
        bool usedRetry,
        byte[] retrySourceConnectionId,
        object peerParametersValue)
    {
        QuicTransportParameterRole receiverRole = (QuicTransportParameterRole)receiverRoleValue;
        QuicTransportParameters peerParameters = (QuicTransportParameters)peerParametersValue;

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            receiverRole,
            initialDestinationConnectionId,
            initialSourceConnectionId,
            usedRetry,
            retrySourceConnectionId,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryValidateConnectionIdBindings_RejectsMismatchedOriginalDestinationConnectionId()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = [0x99],
            InitialSourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
        };

        Assert.False(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
            usedRetry: false,
            ReadOnlySpan<byte>.Empty,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.OriginalDestinationConnectionIdMismatch, validationError);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryValidateConnectionIdBindings_AcceptsZeroLengthInitialSourceConnectionIdMatch()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = [],
        };

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            usedRetry: false,
            ReadOnlySpan<byte>.Empty,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }
}
