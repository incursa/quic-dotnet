namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S10P3-0018")]
public sealed class REQ_QUIC_RFC9000_S10P3_0018
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryFormatTransportParameters_WritesTheServerStatelessResetTokenTuple()
    {
        byte[] statelessResetToken = [
            0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B,
            0x3C, 0x3D, 0x3E, 0x3F];

        QuicTransportParameters parameters = new()
        {
            StatelessResetToken = statelessResetToken,
        };

        Span<byte> destination = stackalloc byte[32];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        byte[] expected = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(0x02, statelessResetToken));

        Assert.Equal(expected.Length, bytesWritten);
        Assert.True(expected.AsSpan().SequenceEqual(destination[..bytesWritten]));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));
        Assert.True(statelessResetToken.AsSpan().SequenceEqual(parsed.StatelessResetToken!));
        Assert.Null(parsed.MaxIdleTimeout);
        Assert.Null(parsed.PreferredAddress);
    }
}
