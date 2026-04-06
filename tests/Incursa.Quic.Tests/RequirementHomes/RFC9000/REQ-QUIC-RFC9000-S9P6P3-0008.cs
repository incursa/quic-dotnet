namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P3-0008")]
public sealed class REQ_QUIC_RFC9000_S9P6P3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_RetainsThePreferredAddressConnectionIdForMigrationUse()
    {
        byte[] connectionId = [0x91, 0x92, 0x93, 0x94];
        byte[] statelessResetToken = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF];

        QuicTransportParameters parameters = new()
        {
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = [0, 0, 0, 0],
                IPv4Port = 0,
                IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                IPv6Port = 8443,
                ConnectionId = connectionId,
                StatelessResetToken = statelessResetToken,
            },
        };

        Span<byte> destination = stackalloc byte[128];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        byte[] expectedIpv4Address = [0, 0, 0, 0];
        byte[] expectedIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06];
        Assert.True(connectionId.AsSpan().SequenceEqual(parsed.PreferredAddress!.ConnectionId));
        Assert.True(parsed.PreferredAddress.IPv4Address.AsSpan().SequenceEqual(expectedIpv4Address));
        Assert.True(parsed.PreferredAddress.IPv6Address.AsSpan().SequenceEqual(expectedIpv6Address));
    }
}
