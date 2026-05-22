namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0326")]
public sealed class REQ_QUIC_RFC9000_0326
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0326")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryValidateConnectionIdBindings_AcceptsReceivedTransportParametersThatMatchObservedConnectionIds()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
            RetrySourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.RetrySourceConnectionId,
        };

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
            usedRetry: true,
            QuicS7P3ConnectionIdBindingTestSupport.RetrySourceConnectionId,
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }
}
