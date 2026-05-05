namespace Incursa.Quic.Tests;

internal static class QuicPreferredAddressRequirementTestSupport
{
    internal const byte PreferredAddressTransportParameterId = 0x0D;
    internal const int PreferredAddressTupleHeaderLength = 2;
    internal const int IPv4AddressOffset = 0;
    internal const int IPv4AddressLength = 4;
    internal const int IPv4PortOffset = IPv4AddressOffset + IPv4AddressLength;
    internal const int PortLength = 2;
    internal const int IPv6AddressOffset = IPv4PortOffset + PortLength;
    internal const int IPv6AddressLength = 16;
    internal const int IPv6PortOffset = IPv6AddressOffset + IPv6AddressLength;
    internal const int ConnectionIdLengthOffset = IPv6PortOffset + PortLength;
    internal const int ConnectionIdOffset = ConnectionIdLengthOffset + 1;
    internal const int StatelessResetTokenLength = 16;

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

        return QuicTransportParameterTestData.BuildTransportParameterTuple(PreferredAddressTransportParameterId, value);
    }

    internal static byte[] FormatPreferredAddressValueAsServer(QuicPreferredAddress preferredAddress)
    {
        byte[] encoded = FormatAsServer(new QuicTransportParameters
        {
            InitialSourceConnectionId = InitialSourceConnectionId,
            PreferredAddress = preferredAddress,
        });

        Assert.True(encoded.Length >= PreferredAddressTupleHeaderLength);
        Assert.Equal(PreferredAddressTransportParameterId, encoded[0]);

        int valueLength = encoded[1];
        Assert.True(valueLength <= encoded.Length - PreferredAddressTupleHeaderLength);
        return encoded.AsSpan(PreferredAddressTupleHeaderLength, valueLength).ToArray();
    }

    internal static bool TryParsePreferredAddressValueAsClient(
        byte[] preferredAddressValue,
        out QuicTransportParameters parsed)
    {
        byte[] encoded = QuicTransportParameterTestData.BuildTransportParameterBlock(
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                0x0F,
                InitialSourceConnectionId),
            QuicTransportParameterTestData.BuildTransportParameterTuple(
                PreferredAddressTransportParameterId,
                preferredAddressValue));

        return QuicTransportParametersCodec.TryParseTransportParameters(
            encoded,
            QuicTransportParameterRole.Client,
            out parsed);
    }
}
