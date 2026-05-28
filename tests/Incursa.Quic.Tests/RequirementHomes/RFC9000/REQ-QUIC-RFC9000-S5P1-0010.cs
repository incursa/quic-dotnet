// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1-0010")]
public sealed class REQ_QUIC_RFC9000_S5P1_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0001")]
    [Trait("Category", "Positive")]
    public void EndpointRoutesShortHeaderPacketsUsingTheRegisteredDestinationConnectionIdLength()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.30",
            localAddress: "192.0.2.30",
            remotePort: 44340,
            localPort: 4433);
        ReadOnlySpan<byte> destinationConnectionId = [0x30, 0x31];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, registeredPath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, destinationConnectionId));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(destinationConnectionId),
            registeredPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0001")]
    [Trait("Category", "Negative")]
    public void EndpointLeavesShortHeaderPacketsUnroutableWhenTheDestinationConnectionIdLengthDoesNotMatchAnyRegisteredRoute()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.30",
            localAddress: "192.0.2.30",
            remotePort: 44340,
            localPort: 4433);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, registeredPath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x30, 0x31]));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram([0x30]),
            registeredPath);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Requirement("REQ-QUIC-RFC9000-S5P1-0011")]
    [Requirement("REQ-QUIC-RFC9000-S5P2P3-0001")]
    [Trait("Category", "Edge")]
    public void EndpointRoutesTheShortestRegisteredShortHeaderDestinationConnectionIdLength()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.31",
            localAddress: "192.0.2.31",
            remotePort: 44341,
            localPort: 4433);
        ReadOnlySpan<byte> destinationConnectionId = [0x30];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, registeredPath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, destinationConnectionId));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(destinationConnectionId),
            registeredPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }
}
