namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0030")]
public sealed class REQ_QUIC_RFC9000_S18P2_0030
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesSixteenBytePreferredAddressIpv6Field()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress());

        Assert.Equal(16, QuicPreferredAddressRequirementTestSupport.IPv6AddressLength);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv6Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv6AddressLength).ToArray());
        Assert.Equal(new byte[] { 0x20, 0xFB }, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv6PortOffset,
            QuicPreferredAddressRequirementTestSupport.PortLength).ToArray());
    }
}
