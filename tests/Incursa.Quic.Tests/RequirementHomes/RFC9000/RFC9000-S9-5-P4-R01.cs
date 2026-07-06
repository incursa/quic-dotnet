// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-5-P4-R01")]
public sealed class REQ_QUIC_RFC9000_S9P5_0003
{
    [Fact]
    [Requirement("RFC9000-S9-5-P4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointRejectsConnectionIdReuseAcrossDifferentDestinationAddresses()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity firstPath = new("203.0.113.170", "198.51.100.170", 443, 61234);
        QuicConnectionPathIdentity secondPath = new("203.0.113.171", "198.51.100.170", 443, 61235);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, [0x40, 0x41]));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));

        Assert.False(endpoint.TryRegisterConnectionId(secondHandle, [0x40, 0x41]));
    }

    [Fact]
    [Requirement("RFC9000-S9-5-P4-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void EndpointRejectsConnectionIdReuseAcrossDifferentDestinationAddressesFuzz()
    {
        (QuicConnectionPathIdentity FirstPath, QuicConnectionPathIdentity SecondPath, byte[] ConnectionId)[] cases =
        [
            (new("203.0.113.170", "198.51.100.170", 443, 61234), new("203.0.113.171", "198.51.100.170", 443, 61235), [0x40, 0x41]),
            (new("203.0.113.172", "198.51.100.172", 443, 61236), new("203.0.113.173", "198.51.100.172", 443, 61237), [0x42, 0x43, 0x44]),
            (new("203.0.113.174", "198.51.100.174", 443, 61238), new("203.0.113.175", "198.51.100.174", 443, 61239), [0x45]),
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
