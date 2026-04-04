namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9002-S6P3-0003")]
public sealed class REQ_QUIC_RFC9002_S6P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryValidateConnectionIdBindings_AcceptsMatchingRetrySourceConnectionIdAfterRetry()
    {
        QuicTransportParameters peerParameters = new()
        {
            OriginalDestinationConnectionId = [0x10, 0x11],
            InitialSourceConnectionId = [0x20, 0x21],
            RetrySourceConnectionId = [0x30, 0x31],
        };

        Assert.True(QuicTransportParametersCodec.TryValidateConnectionIdBindings(
            QuicTransportParameterRole.Client,
            initialDestinationConnectionId: [0x10, 0x11],
            initialSourceConnectionId: [0x20, 0x21],
            usedRetry: true,
            retrySourceConnectionId: [0x30, 0x31],
            peerParameters,
            out QuicConnectionIdBindingValidationError validationError));

        Assert.Equal(QuicConnectionIdBindingValidationError.None, validationError);
    }
}
