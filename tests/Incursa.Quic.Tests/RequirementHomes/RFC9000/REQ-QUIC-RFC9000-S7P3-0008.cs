namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0008")]
public sealed class REQ_QUIC_RFC9000_S7P3_0008
{
    [Theory]
    [MemberData(nameof(QuicTransportParametersTests.MismatchedConnectionIdBindingCases), MemberType = typeof(QuicTransportParametersTests))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0008">An endpoint MUST treat the following as a connection error of type TRANSPORT_PARAMETER_ERROR or PROTOCOL_VIOLATION:</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S7P3-0008")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryValidateConnectionIdBindings_RejectsMismatchedConnectionIdBindings(
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
