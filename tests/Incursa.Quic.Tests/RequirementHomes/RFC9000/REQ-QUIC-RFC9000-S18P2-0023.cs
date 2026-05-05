namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0023")]
public sealed class REQ_QUIC_RFC9000_S18P2_0023
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_PreservesStatelessResetTokenAssociatedWithPreferredConnectionId()
    {
        byte[] expectedConnectionId = [0x44, 0x45, 0x46, 0x47];
        byte[] expectedStatelessResetToken = [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F];
        byte[] value = QuicPreferredAddressRequirementTestSupport.FormatPreferredAddressValueAsServer(
            QuicPreferredAddressRequirementTestSupport.CreatePreferredAddress(
                preferredConnectionId: expectedConnectionId,
                statelessResetToken: expectedStatelessResetToken));

        Assert.True(QuicPreferredAddressRequirementTestSupport.TryParsePreferredAddressValueAsClient(
            value,
            out QuicTransportParameters parsed));

        Assert.NotNull(parsed.PreferredAddress);
        Assert.Equal(expectedConnectionId, parsed.PreferredAddress!.ConnectionId);
        Assert.Equal(expectedStatelessResetToken, parsed.PreferredAddress.StatelessResetToken);
    }
}
