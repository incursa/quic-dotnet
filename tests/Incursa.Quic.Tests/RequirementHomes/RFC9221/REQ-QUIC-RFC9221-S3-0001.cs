namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9221-S3-0001")]
[Requirement("REQ-QUIC-RFC9221-S3-0002")]
[Requirement("REQ-QUIC-RFC9221-S3-0003")]
[Requirement("REQ-QUIC-RFC9221-S3-0008")]
public sealed class REQ_QUIC_RFC9221_S3_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_RoundTripsMaxDatagramFrameSize()
    {
        QuicTransportParameters parameters = new()
        {
            MaxDatagramFrameSize = 65_535,
        };

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterTuple(
            0x20,
            QuicVarintTestData.EncodeMinimal(65_535));

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Client,
            destination,
            out int bytesWritten));

        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));
        Assert.Equal(65_535UL, parsed.MaxDatagramFrameSize);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryParseTransportParameters_DefaultsMissingMaxDatagramFrameSizeToUnsupported()
    {
        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            [],
            QuicTransportParameterRole.Server,
            out QuicTransportParameters parsed));

        Assert.Null(parsed.MaxDatagramFrameSize);
        Assert.Equal(0UL, parsed.MaxDatagramFrameSize ?? 0);
    }
}
