namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P6P3-0011")]
public sealed class REQ_QUIC_RFC9000_S9P6P3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointRoutesThePreferredAddressConnectionIdAcrossPathMigration()
    {
        byte[] initialSourceConnectionId = [0x10, 0x11, 0x12, 0x13];
        byte[] preferredConnectionId = [0x20, 0x21, 0x22, 0x23];
        byte[] statelessResetToken = [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F];
        byte[] preferredIpv4Address = [198, 51, 100, 34];
        byte[] preferredIpv6Address = [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x22];
        QuicTransportParameters transportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId,
            PreferredAddress = new QuicPreferredAddress
            {
                IPv4Address = preferredIpv4Address,
                IPv4Port = 9447,
                IPv6Address = preferredIpv6Address,
                IPv6Port = 9557,
                ConnectionId = preferredConnectionId,
                StatelessResetToken = statelessResetToken,
            },
        };

        Span<byte> destination = stackalloc byte[256];
        Assert.True(QuicTransportParametersCodec.TryFormatTransportParameters(
            transportParameters,
            QuicTransportParameterRole.Server,
            destination,
            out int bytesWritten));

        Assert.True(QuicTransportParametersCodec.TryParseTransportParameters(
            destination[..bytesWritten],
            QuicTransportParameterRole.Client,
            out QuicTransportParameters parsedTransportParameters));

        Assert.NotNull(parsedTransportParameters.PreferredAddress);

        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = new("203.0.113.34", "198.51.100.34", 443, 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.35", "198.51.100.35", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, parsedTransportParameters.PreferredAddress!.ConnectionId));

        QuicConnectionIngressResult activePathResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x20, 0x21, 0x22, 0x23, 0xAA]),
            activePath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, activePathResult.Disposition);
        Assert.Equal(handle, activePathResult.Handle);

        Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

        QuicConnectionIngressResult migratedPathResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x20, 0x21, 0x22, 0x23, 0xBB]),
            migratedPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, migratedPathResult.Disposition);
        Assert.Equal(handle, migratedPathResult.Handle);
    }
}
