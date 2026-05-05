namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0028")]
public sealed class REQ_QUIC_RFC9000_S18P2_0028
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesFourBytePreferredAddressIpv4Field()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress());

        Assert.Equal(4, QuicPreferredAddressRequirementTestSupport.IPv4AddressLength);
        Assert.Equal(QuicPreferredAddressRequirementTestSupport.PreferredIpv4Address, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4AddressOffset,
            QuicPreferredAddressRequirementTestSupport.IPv4AddressLength).ToArray());
        Assert.Equal(new byte[] { 0x01, 0xBB }, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4PortOffset,
            QuicPreferredAddressRequirementTestSupport.PortLength).ToArray());
    }
}
