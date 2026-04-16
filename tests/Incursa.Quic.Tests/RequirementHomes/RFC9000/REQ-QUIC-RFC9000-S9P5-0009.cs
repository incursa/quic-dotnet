namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0009")]
public sealed class REQ_QUIC_RFC9000_S9P5_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointCanRouteAProvidedConnectionIdWhenThePeerSourceAddressChangesAndTheLocalAddressStaysTheSame()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = new("203.0.113.210", "198.51.100.210", 443, 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.211", "198.51.100.210", 443, 61234);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x50, 0x51]));

        QuicConnectionIngressResult preMigrationResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x50, 0x51, 0xAA]),
            activePath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, preMigrationResult.Disposition);
        Assert.Equal(handle, preMigrationResult.Handle);

        Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

        QuicConnectionIngressResult postMigrationResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x50, 0x51, 0xBB]),
            migratedPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, postMigrationResult.Disposition);
        Assert.Equal(handle, postMigrationResult.Handle);
    }
}
