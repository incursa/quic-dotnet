namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0029")]
public sealed class REQ_QUIC_RFC9000_S18P2_0029
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryFormatTransportParameters_WritesTwoBytePreferredAddressIpv4PortField()
    {
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(preferredIpv4Port: 443));

        Assert.Equal(2, QuicPreferredAddressRequirementTestSupport.PortLength);
        Assert.Equal(new byte[] { 0x01, 0xBB }, value.AsSpan(
            QuicPreferredAddressRequirementTestSupport.IPv4PortOffset,
            QuicPreferredAddressRequirementTestSupport.PortLength).ToArray());

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value,
            out QuicTransportParameters parsed));
        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal((ushort)443, parsed.PreferredAddress!.IPv4Port);
    }
}
