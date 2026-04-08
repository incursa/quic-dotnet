namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
public sealed class REQ_QUIC_RFC9000_S4P1_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseAndFormatTransportParameters_PreservesInitialFlowControlLimits()
    {
        QuicTransportParameters parameters = new()
        {
            InitialMaxData = 16,
            InitialMaxStreamDataBidiLocal = 8,
            InitialMaxStreamDataBidiRemote = 10,
            InitialMaxStreamDataUni = 12,
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

        Assert.Equal(16UL, parsedParameters.InitialMaxData);
        Assert.Equal(8UL, parsedParameters.InitialMaxStreamDataBidiLocal);
        Assert.Equal(10UL, parsedParameters.InitialMaxStreamDataBidiRemote);
        Assert.Equal(12UL, parsedParameters.InitialMaxStreamDataUni);
    }
}
