// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;
using System.Net.Sockets;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14-0008">In IPv4 [IPv4], the Don't Fragment (DF) bit MUST be set if possible, to prevent fragmentation on the path.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14-0008")]
public sealed class REQ_QUIC_RFC9000_S14_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicConnectionEndpointHost_EnablesDontFragmentOnAnIpv4Socket()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        QuicConnectionPathIdentity pathIdentity = new("127.0.0.1", "127.0.0.1", 12345, 54321);

        Assert.False(socket.DontFragment);

        using QuicConnectionEndpointHost host = new(endpoint, socket, pathIdentity);

        Assert.True(socket.DontFragment);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void QuicListenerHost_EnablesDontFragmentOnItsIpv4Socket()
    {
        IPEndPoint listenEndPoint = new(IPAddress.Loopback, 0);

        using QuicListenerHost listenerHost = new(
            listenEndPoint,
            [SslApplicationProtocol.Http3],
            (_, _, _) => ValueTask.FromResult(new QuicServerConnectionOptions()),
            listenBacklog: 1);

        Socket socket = listenerHost.Socket;

        Assert.True(socket.DontFragment);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryEnableDontFragmentIfPossible_ReturnsFalseForIpv6SocketsWithoutThrowing()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        using Socket socket = new(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);

        Assert.False(QuicSocketFragmentationControl.TryEnableDontFragmentIfPossible(socket));
    }

}
