namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P3-0002")]
public sealed class REQ_QUIC_RFC9000_S5P2P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerPreferredAddressValueRoundTripsThroughClientParsing()
    {
        QuicPreferredAddress preferredAddress = QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress();
        byte[] preferredAddressValue = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(preferredAddress);

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            preferredAddressValue,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(preferredAddress.IPv4Address, parsed.PreferredAddress!.IPv4Address);
        Assert.Equal(preferredAddress.IPv4Port, parsed.PreferredAddress.IPv4Port);
        Assert.Equal(preferredAddress.IPv6Address, parsed.PreferredAddress.IPv6Address);
        Assert.Equal(preferredAddress.IPv6Port, parsed.PreferredAddress.IPv6Port);
        Assert.Equal(preferredAddress.ConnectionId, parsed.PreferredAddress.ConnectionId);
        Assert.Equal(preferredAddress.StatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
    }
}
