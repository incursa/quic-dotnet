namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
public sealed class REQ_QUIC_RFC9000_S4P6_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P6-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAndFormatTransportParameters_PreservesInitialStreamLimits()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxStreamsBidi = 2,
            InitialMaxStreamsUni = 3,
        };

        Span<byte> destination = stackalloc byte[64];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsedParameters));

        Assert.Equal(2UL, parsedParameters.InitialMaxStreamsBidi);
        Assert.Equal(3UL, parsedParameters.InitialMaxStreamsUni);
    }
}
