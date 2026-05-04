namespace Incursa.Quic.Tests;

internal static class QuicPreferredAddressRequirementTestSupport
{
    internal static readonly byte[] InitialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
    internal static readonly byte[] PreferredConnectionId = [0x20, 0x21, 0x22, 0x23];
    internal static readonly byte[] PreferredIpv4Address = [192, 0, 2, 1];
    internal static readonly byte[] PreferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06];
    internal static readonly byte[] StatelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];

    internal static QuicTransportParameters CreateServerTransportParameters(
        byte[]? initialSourceConnectionId = null,
        byte[]? preferredConnectionId = null,
        byte[]? preferredIpv4Address = null,
        ushort preferredIpv4Port = 443,
        byte[]? preferredIpv6Address = null,
        ushort preferredIpv6Port = 8443,
        byte[]? statelessResetToken = null)
    {
        return new QuicTransportParameters
        {
            InitialSourceConnectionId = initialSourceConnectionId ?? InitialSourceConnectionId,
            PreferredAddress = CreatePreferredAddress(
                preferredConnectionId,
                preferredIpv4Address,
                preferredIpv4Port,
                preferredIpv6Address,
                preferredIpv6Port,
                statelessResetToken),
        };
    }

    internal static QuicPreferredAddress CreatePreferredAddress(
        byte[]? preferredConnectionId = null,
        byte[]? preferredIpv4Address = null,
        ushort preferredIpv4Port = 443,
        byte[]? preferredIpv6Address = null,
        ushort preferredIpv6Port = 8443,
        byte[]? statelessResetToken = null)
    {
        return new QuicPreferredAddress
        {
            IPv4Address = preferredIpv4Address ?? PreferredIpv4Address,
            IPv4Port = preferredIpv4Port,
            IPv6Address = preferredIpv6Address ?? PreferredIpv6Address,
            IPv6Port = preferredIpv6Port,
            ConnectionId = preferredConnectionId ?? PreferredConnectionId,
            StatelessResetToken = statelessResetToken ?? StatelessResetToken,
        };
    }

    internal static byte[] FormatAsServer(QuicTransportParameters parameters)
    {
        byte[] encoded = new byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            parameters,
            QuicTransportParameterRole.Server,
            encoded,
            out int bytesWritten));

        return encoded[..bytesWritten];
    }

    internal static byte[] BuildPreferredAddressTuple(QuicPreferredAddress preferredAddress)
    {
        byte[] value = QuicTransportParameterTestData.BuildPreferredAddressValue(
            preferredAddress.IPv4Address,
            preferredAddress.IPv4Port,
            preferredAddress.IPv6Address,
            preferredAddress.IPv6Port,
            preferredAddress.ConnectionId,
            preferredAddress.StatelessResetToken);

        return QuicTransportParameterTestData.BuildTransportParameterTuple(0x0D, value);
    }
}
