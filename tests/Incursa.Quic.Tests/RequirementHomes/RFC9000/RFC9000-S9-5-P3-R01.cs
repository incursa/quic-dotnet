// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-5-P3-R01")]
public sealed class REQ_QUIC_RFC9000_0515
{
    [Fact]
    [Requirement("RFC9000-S9-5-P3-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointRejectsConnectionIdReuseAcrossDifferentLocalAddresses()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity firstPath = new("203.0.113.160", "198.51.100.160", 443, 61234);
        QuicConnectionPathIdentity secondPath = new("203.0.113.160", "198.51.100.161", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x30, 0x31]));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));

        Assert.False(endpoint.TryRegisterConnectionId(secondHandle, [0x30, 0x31]));
    }

    [Fact]
    [Requirement("RFC9000-S9-5-P3-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void EndpointRejectsConnectionIdReuseAcrossDifferentLocalAddressesFuzz()
    {
        (QuicConnectionPathIdentity FirstPath, QuicConnectionPathIdentity SecondPath, byte[] ConnectionId)[] cases =
        [
            (new("203.0.113.160", "198.51.100.160", 443, 61234), new("203.0.113.160", "198.51.100.161", 443, 61235), [0x30, 0x31]),
            (new("203.0.113.162", "198.51.100.162", 443, 61236), new("203.0.113.162", "198.51.100.163", 443, 61237), [0x32, 0x33, 0x34]),
            (new("203.0.113.164", "198.51.100.164", 443, 61238), new("203.0.113.164", "198.51.100.165", 443, 61239), [0x35]),
        ];

        foreach ((QuicConnectionPathIdentity firstPath, QuicConnectionPathIdentity secondPath, byte[] connectionId) in cases)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
            QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();

            Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
            Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
            Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
            Assert.True(endpoint.TryRegisterConnectionId(firstHandle, connectionId));
            Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));

            Assert.False(endpoint.TryRegisterConnectionId(secondHandle, connectionId));
        }
    }
}
