namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0012")]
public sealed class REQ_QUIC_RFC9000_S9P5_0012
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointCanRouteANewConnectionIdThatWasProvidedBeforeMigration()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = new("203.0.113.200", "198.51.100.200", 443, 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.201", "198.51.100.201", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x70, 0x71]));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x80, 0x81]));

        QuicConnectionIngressResult preMigrationResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x80, 0x81, 0xAA]),
            activePath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, preMigrationResult.Disposition);
        Assert.Equal(handle, preMigrationResult.Handle);

        Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

        QuicConnectionIngressResult postMigrationResult = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0x80, 0x81, 0xBB]),
            migratedPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, postMigrationResult.Disposition);
        Assert.Equal(handle, postMigrationResult.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointRejectsPacketsForANewConnectionIdThatWasNeverProvidedBeforeMigration()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = new("203.0.113.202", "198.51.100.202", 443, 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.203", "198.51.100.203", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x90, 0x91]));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, [0xA0, 0xA1, 0xCC]),
            migratedPath);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Equal(QuicConnectionEndpointHandlingKind.None, result.HandlingKind);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointCanRouteTheMaximumLengthConnectionIdAfterItWasProvidedBeforeMigration()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = new("203.0.113.204", "198.51.100.204", 443, 61234);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.205", "198.51.100.205", 443, 61235);
        byte[] maximumLengthConnectionId = Enumerable.Range(0, QuicConnectionIdKey.MaximumLength)
            .Select(value => (byte)(0xB0 + value))
            .ToArray();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, maximumLengthConnectionId));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, migratedPath));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicHeaderTestData.BuildShortHeader(0x00, maximumLengthConnectionId),
            migratedPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }
}
