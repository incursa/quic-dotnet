namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
public sealed class REQ_QUIC_RFC9000_S7P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_EmitsOriginalDestinationConnectionIdFromServer()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(parameters.OriginalDestinationConnectionId, parsed.OriginalDestinationConnectionId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryFormatTransportParameters_RejectsOriginalDestinationConnectionIdFromClient()
    {
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = QuicS7P3ConnectionIdBindingTestSupport.InitialDestinationConnectionId,
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(0, bytesWritten);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S7P3-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    public void TryFormatTransportParameters_RoundTripsMaximumLengthOriginalDestinationConnectionId()
    {
        byte[] connectionId = Enumerable.Range(0, 20).Select(value => (byte)value).ToArray();
        QuicTransportParameters parameters = new()
        {
            OriginalDestinationConnectionId = connectionId,
        };

        QuicTransportParameters parsed = QuicS7P3ConnectionIdBindingTestSupport.FormatAndParse(
            parameters,
            QuicTransportParameterRole.Server,
            QuicTransportParameterRole.Client);

        Assert.Equal(connectionId, parsed.OriginalDestinationConnectionId);
    }
}
