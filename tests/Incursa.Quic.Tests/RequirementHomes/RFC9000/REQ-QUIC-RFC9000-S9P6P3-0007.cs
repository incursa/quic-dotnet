namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P3-0007")]
public sealed class REQ_QUIC_RFC9000_S9P6P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseTransportParameters_PreservesPreferredAddressConnectionIdAcrossDifferentAddressBytes()
    {
        byte[] connectionId = [0x10, 0x20, 0x30, 0x40];
        byte[] statelessResetToken = [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F];

        byte[] preferredAddressBlockA = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0D,
                QuicTransportParameterTestData.BuildPreferredAddressValue(
                    ipv4Address: [192, 0, 2, 1],
                    ipv4Port: 443,
                    ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                    ipv6Port: 8443,
                    connectionId: connectionId,
                    statelessResetToken: statelessResetToken)));

        byte[] preferredAddressBlockB = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0D,
                QuicTransportParameterTestData.BuildPreferredAddressValue(
                    ipv4Address: [198, 51, 100, 2],
                    ipv4Port: 444,
                    ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x07],
                    ipv6Port: 8444,
                    connectionId: connectionId,
                    statelessResetToken: statelessResetToken)));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            preferredAddressBlockA,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedA));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            preferredAddressBlockB,
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedB));

        Assert.NotNull(parsedA.PreferredAddress);
        Assert.NotNull(parsedB.PreferredAddress);
        Assert.True(connectionId.AsSpan().SequenceEqual(parsedA.PreferredAddress!.ConnectionId));
        Assert.True(connectionId.AsSpan().SequenceEqual(parsedB.PreferredAddress!.ConnectionId));
        Assert.False(parsedA.PreferredAddress.IPv4Address.AsSpan().SequenceEqual(parsedB.PreferredAddress.IPv4Address));
        Assert.False(parsedA.PreferredAddress.IPv6Address.AsSpan().SequenceEqual(parsedB.PreferredAddress.IPv6Address));
    }
}
