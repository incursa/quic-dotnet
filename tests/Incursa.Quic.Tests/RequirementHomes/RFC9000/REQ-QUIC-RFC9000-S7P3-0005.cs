namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
public sealed class REQ_QUIC_RFC9000_S7P3_0005
{
    [Theory]
    [MemberData(nameof(QuicTransportParameterTestData.MatchingConnectionIdBindingCases), MemberType = typeof(QuicTransportParameterTestData))]
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0005">The values provided by a peer for these transport parameters MUST match the values that an endpoint used in the Destination and Source Connection ID fields of Initial packets that it sent (and received, for servers).</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S7P3-0006">Endpoints MUST validate that received transport parameters match received connection ID values.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S7P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0006")]
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
}
