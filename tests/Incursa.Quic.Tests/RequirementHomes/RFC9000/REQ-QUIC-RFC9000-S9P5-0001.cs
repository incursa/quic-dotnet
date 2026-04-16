namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0001")]
public sealed class REQ_QUIC_RFC9000_S9P5_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointCanRegisterDistinctConnectionIdsOnDistinctPaths()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity firstPath = new("203.0.113.150", "198.51.100.150", 443, 61234);
        QuicConnectionPathIdentity secondPath = new("203.0.113.151", "198.51.100.151", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x10, 0x11]));
        Assert.True(endpoint.TryRegisterConnectionId(secondHandle, [0x20, 0x21]));

        QuicConnectionIngressResult firstResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x10, 0x11, 0xAA]),
            firstPath);

        QuicConnectionIngressResult secondResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x20, 0x21, 0xBB]),
            secondPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, firstResult.Disposition);
        Assert.Equal(firstHandle, firstResult.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, secondResult.Disposition);
        Assert.Equal(secondHandle, secondResult.Handle);
    }
}
