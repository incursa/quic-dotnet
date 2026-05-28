// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

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

        byte[] initialDestinationConnectionId = host.InitialDestinationConnectionId;
        byte[] routeConnectionId = host.RouteConnectionId;
        QuicConnection connection = host.Connection;
        QuicConnectionRuntime runtime = connection.Runtime;
        QuicHandshakeFlowCoordinator handshakeFlowCoordinator = runtime.HandshakeFlowCoordinator;

        Assert.Equal(8, initialDestinationConnectionId.Length);
        Assert.Equal(8, routeConnectionId.Length);
        Assert.False(initialDestinationConnectionId.AsSpan().SequenceEqual(routeConnectionId));
        Assert.Equal(initialDestinationConnectionId, handshakeFlowCoordinator.InitialDestinationConnectionId.ToArray());
        Assert.Empty(handshakeFlowCoordinator.DestinationConnectionId.ToArray());
        Assert.Equal(routeConnectionId, handshakeFlowCoordinator.SourceConnectionId.ToArray());
        Assert.NotNull(runtime.InitialPacketProtection);
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

        byte[] firstInitialDestinationConnectionId = firstHost.InitialDestinationConnectionId;
        byte[] firstRouteConnectionId = firstHost.RouteConnectionId;
        byte[] secondInitialDestinationConnectionId = secondHost.InitialDestinationConnectionId;
        byte[] secondRouteConnectionId = secondHost.RouteConnectionId;

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
}
