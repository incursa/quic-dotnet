namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9287-S3-0001")]
public sealed class REQ_QUIC_RFC9287_S3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_EmitsGreaseQuicBitAsEmptyParameter()
    {
        QuicTransportParameters parameters = new()
        {
            GreaseQuicBit = true,
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(0x2AB2, []);

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryFormatTransportParameters_OmitsGreaseQuicBitWhenDisabled()
    {
        QuicTransportParameters parameters = new()
        {
            MaxIdleTimeout = 17,
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x01,
            QuicVarintTestData.EncodeMinimal(17));

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryFormatTransportParameters_EmitsGreaseQuicBitForTheSmallestBoundaryClientShape()
    {
        QuicTransportParameters parameters = new()
        {
            ActiveConnectionIdLimit = 2,
            GreaseQuicBit = true,
            MaxUdpPayloadSize = 1200,
            InitialSourceConnectionId = [0x01],
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
            out QuicTransportParameters parsed));

        Assert.True(parsed.GreaseQuicBit);
        Assert.Equal(1200UL, parsed.MaxUdpPayloadSize);
        Assert.Equal(2UL, parsed.ActiveConnectionIdLimit);
        Assert.Single(parsed.InitialSourceConnectionId!);
        Assert.Equal((byte)0x01, parsed.InitialSourceConnectionId![0]);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryFormatTransportParameters_EmitsGreaseQuicBitAcrossRepresentativeShapes()
    {
        QuicGreaseQuicBitFuzzSupport.FuzzTransportParameterCodecRoundTripsAndValidatesGreaseBit();
    }
}
