namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0020")]
public sealed class REQ_QUIC_RFC9000_S18P2_0020
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void TryParseTransportParameters_AcceptsPreferredAddressWithZeroedIpv4Family()
    {
        byte[] expectedIpv4Address = [0, 0, 0, 0];
        byte[] expectedIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06];
        byte[] expectedConnectionId = [0xAA, 0xBB];
        byte[] expectedResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0x90 + value)).ToArray();

        QuicTransportParameters parameters = new()
        {
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = expectedIpv4Address,
                IPv4Port = 0,
                IPv6Address = expectedIpv6Address,
                IPv6Port = 8443,
                ConnectionId = expectedConnectionId,
                StatelessResetToken = expectedResetToken,
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
        QuicPreferredAddress preferredAddress = parsed.PreferredAddress!;
        Assert.Equal(expectedIpv4Address, preferredAddress.IPv4Address);
        Assert.Equal((ushort)0, preferredAddress.IPv4Port);
        Assert.Equal(expectedIpv6Address, preferredAddress.IPv6Address);
        Assert.Equal((ushort)8443, preferredAddress.IPv6Port);
        Assert.Equal(expectedConnectionId, preferredAddress.ConnectionId);
        Assert.Equal(expectedResetToken, preferredAddress.StatelessResetToken);
    }
}
