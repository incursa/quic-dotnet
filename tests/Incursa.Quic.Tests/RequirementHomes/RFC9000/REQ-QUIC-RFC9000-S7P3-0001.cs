namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
public sealed class REQ_QUIC_RFC9000_S7P3_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_AuthenticatesHandshakeConnectionIdChoices()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
            InitialSourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.ServerInitialSourceConnectionId,
            RetrySourceConnectionId = QuicS7P3ConnectionIdBindingTestSupport.RetrySourceConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(parameters.OriginalDestinationConnectionId, parsed.OriginalDestinationConnectionId);
        Assert.Equal(parameters.InitialSourceConnectionId, parsed.InitialSourceConnectionId);
        Assert.Equal(parameters.RetrySourceConnectionId, parsed.RetrySourceConnectionId);
    }
}
