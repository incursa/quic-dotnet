namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0007")]
public sealed class REQ_QUIC_RFC9000_S7P3_0007
{
    [Theory]
    [MemberData(nameof(QuicTransportParameterTestData.MissingConnectionIdBindingCases), MemberType = typeof(QuicTransportParameterTestData))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0007">An endpoint MUST treat the absence of the initial_source_connection_id transport parameter from either endpoint or the absence of the original_destination_connection_id transport parameter from the server as a connection error of type TRANSPORT_PARAMETER_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S7P3-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryValidateConnectionIdBindings_RejectsMissingConnectionIdBindings(
        QuicTransportParameterRole receiverRole,
        byte[] initialDestinationConnectionId,
        byte[] initialSourceConnectionId,
        bool usedRetry,
        byte[] retrySourceConnectionId,
        QuicTransportParameters peerParameters,
        QuicConnectionIdBindingValidationError expectedError)
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
