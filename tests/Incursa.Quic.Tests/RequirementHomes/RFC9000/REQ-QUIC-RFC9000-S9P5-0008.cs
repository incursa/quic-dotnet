using System.Reflection;

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0008")]
public sealed class REQ_QUIC_RFC9000_S9P5_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ClientHostPropagatesItsBootstrapCidValuesWithoutMutation()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings settings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost host = new(settings);

        byte[] initialDestinationConnectionId = GetPrivateField<byte[]>(host, "initialDestinationConnectionId");
        byte[] routeConnectionId = GetPrivateField<byte[]>(host, "routeConnectionId");
        QuicConnection connection = GetPrivateField<QuicConnection>(host, "connection");
        QuicConnectionRuntime runtime = GetPrivateField<QuicConnectionRuntime>(connection, "runtime");
        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = GetPrivateField<QuicHandshakeFlowCoordinator>(runtime, "handshakeFlowCoordinator");

        Assert.Equal(8, initialDestinationConnectionId.Length);
        Assert.Equal(8, routeConnectionId.Length);
        Assert.False(initialDestinationConnectionId.AsSpan().SequenceEqual(routeConnectionId));
        Assert.Equal(initialDestinationConnectionId, GetPrivateField<byte[]>(handshakeFlowCoordinator, "initialDestinationConnectionId"));
        Assert.Empty(GetPrivateField<byte[]>(handshakeFlowCoordinator, "destinationConnectionId"));
        Assert.Equal(routeConnectionId, GetPrivateField<byte[]>(handshakeFlowCoordinator, "sourceConnectionId"));
        Assert.NotNull(GetPrivateField<QuicInitialPacketProtection>(runtime, "initialPacketProtection"));
        Assert.Equal(QuicTlsRole.Client, runtime.TlsState.Role);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ClientHostBootstrapCidValuesAreFreshAcrossIdenticalConstructions()
    {
        var remoteEndPoint = QuicLoopbackEstablishmentTestSupport.GetUnusedLoopbackEndPoint();
        QuicClientConnectionSettings firstSettings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");
        QuicClientConnectionSettings secondSettings = QuicClientConnectionOptionsValidator.Capture(
            QuicLoopbackEstablishmentTestSupport.CreateSupportedClientOptions(remoteEndPoint),
            "options");

        await using QuicClientConnectionHost firstHost = new(firstSettings);
        await using QuicClientConnectionHost secondHost = new(secondSettings);

        byte[] firstInitialDestinationConnectionId = GetPrivateField<byte[]>(firstHost, "initialDestinationConnectionId");
        byte[] firstRouteConnectionId = GetPrivateField<byte[]>(firstHost, "routeConnectionId");
        byte[] secondInitialDestinationConnectionId = GetPrivateField<byte[]>(secondHost, "initialDestinationConnectionId");
        byte[] secondRouteConnectionId = GetPrivateField<byte[]>(secondHost, "routeConnectionId");

        Assert.Equal(8, firstInitialDestinationConnectionId.Length);
        Assert.Equal(8, firstRouteConnectionId.Length);
        Assert.Equal(8, secondInitialDestinationConnectionId.Length);
        Assert.Equal(8, secondRouteConnectionId.Length);
        Assert.False(firstInitialDestinationConnectionId.AsSpan().SequenceEqual(firstRouteConnectionId));
        Assert.False(secondInitialDestinationConnectionId.AsSpan().SequenceEqual(secondRouteConnectionId));
        Assert.False(firstInitialDestinationConnectionId.AsSpan().SequenceEqual(secondInitialDestinationConnectionId));
        Assert.False(firstRouteConnectionId.AsSpan().SequenceEqual(secondRouteConnectionId));
        Assert.False(firstInitialDestinationConnectionId.AsSpan().SequenceEqual(secondRouteConnectionId));
        Assert.False(firstRouteConnectionId.AsSpan().SequenceEqual(secondInitialDestinationConnectionId));
    }

    private static T GetPrivateField<T>(object target, string fieldName)
    {
        FieldInfo? field = target.GetType().GetField(fieldName, BindingFlags.Instance | BindingFlags.NonPublic);
        Assert.NotNull(field);
        return Assert.IsType<T>(field.GetValue(target));
    }
}
