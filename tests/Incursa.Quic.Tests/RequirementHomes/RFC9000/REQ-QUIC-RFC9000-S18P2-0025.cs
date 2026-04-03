namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S18P2-0025")]
public sealed class REQ_QUIC_RFC9000_S18P2_0025
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void TryParseTransportParameters_RejectsPreferredAddressWithZeroLengthConnectionId()
    {
        byte[] preferredAddressValue = QuicTransportParameterTestData.BuildPreferredAddressValue(
            ipv4Address: [192, 0, 2, 1],
            ipv4Port: 443,
            ipv6Address: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
            ipv6Port: 8443,
            connectionId: [],
            statelessResetToken: Enumerable.Range(0, 16).Select(value => (byte)(0xA0 + value)).ToArray());

        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, preferredAddressValue);

        Assert.False(QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out _));

        Assert.False(QuicTransportParametersCodec.TryFormatTransportParameters(
            new QuicTransportParameters
            {
                PreferredAddress = new QuicPreferredAddress
                {
                    IPv4Address = [192, 0, 2, 1],
                    IPv4Port = 443,
                    IPv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06],
                    IPv6Port = 8443,
                    ConnectionId = [],
                    StatelessResetToken = Enumerable.Range(0, 16).Select(value => (byte)(0xA0 + value)).ToArray(),
                },
            },
            QuicTransportParameterRole.Server,
            stackalloc byte[128],
            out _));
    }
}
