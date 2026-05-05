namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0021")]
public sealed class REQ_QUIC_RFC9000_S18P2_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesPreferredAddressIpBytesInNetworkByteOrder()
    {
        byte[] expectedIpv4Address = [192, 0, 2, 123];
        byte[] expectedIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x10, 0x00, 0x20, 0x00, 0x30, 0x00, 0x40, 0x00, 0x50, 0x00, 0x7B];
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
            preferredIpv4Address: expectedIpv4Address,
            preferredIpv6Address: expectedIpv6Address);

        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

        Assert.Equal(expectedIpv4Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
        Assert.Equal(expectedIpv6Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(expectedIpv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(expectedIpv6Address, parsed.PreferredAddress.IPv6Address);
    }
}
