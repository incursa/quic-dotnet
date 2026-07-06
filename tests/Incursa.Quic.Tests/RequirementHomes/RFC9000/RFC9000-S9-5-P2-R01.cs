// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-5-P2-R01")]
public sealed class REQ_QUIC_RFC9000_S9P5_0001
{
    [Fact]
    [Requirement("RFC9000-S9-5-P2-R01")]
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

    [Fact]
    [Requirement("RFC9000-S9-5-P2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void EndpointCanRegisterDistinctConnectionIdsOnDistinctPathsFuzz()
    {
        (QuicConnectionPathIdentity FirstPath, QuicConnectionPathIdentity SecondPath, byte[] FirstConnectionId, byte[] SecondConnectionId)[] cases =
        [
            (new("203.0.113.150", "198.51.100.150", 443, 61234), new("203.0.113.151", "198.51.100.151", 443, 61235), [0x10, 0x11], [0x20, 0x21]),
            (new("203.0.113.152", "198.51.100.152", 443, 61236), new("203.0.113.153", "198.51.100.153", 444, 61237), [0x12, 0x13, 0x14], [0x22, 0x23, 0x24]),
            (new("203.0.113.154", "198.51.100.154", 443, 61238), new("203.0.113.155", "198.51.100.155", 445, 61239), [0x15], [0x25]),
        ];

        foreach ((QuicConnectionPathIdentity firstPath, QuicConnectionPathIdentity secondPath, byte[] firstConnectionId, byte[] secondConnectionId) in cases)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(2);
            using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
            QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();

            Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
            Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
            Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, firstPath));
            Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, secondPath));
            Assert.True(endpoint.TryRegisterConnectionId(firstHandle, firstConnectionId));
            Assert.True(endpoint.TryRegisterConnectionId(secondHandle, secondConnectionId));

            QuicConnectionIngressResult firstResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, firstConnectionId),
                firstPath);
            QuicConnectionIngressResult secondResult = endpoint.ReceiveDatagram(
                QuicHeaderTestData.BuildShortHeader(0x00, secondConnectionId),
                secondPath);

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, firstResult.Disposition);
            Assert.Equal(firstHandle, firstResult.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, secondResult.Disposition);
            Assert.Equal(secondHandle, secondResult.Handle);
        }
    }
}
