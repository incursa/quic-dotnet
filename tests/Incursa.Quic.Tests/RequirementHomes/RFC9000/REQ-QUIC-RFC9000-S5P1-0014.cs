// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1-0014")]
public sealed class REQ_QUIC_RFC9000_S5P1_0014
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointRoutesPacketsForARegisteredZeroLengthConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.20",
            localAddress: "192.0.2.20",
            remotePort: 44331,
            localPort: 4433);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, registeredPath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, ReadOnlySpan<byte>.Empty));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
                remoteAddress: "203.0.113.21",
                localAddress: "192.0.2.20",
                remotePort: 44332,
                localPort: 4433));

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointRejectsASecondConcurrentZeroLengthConnectionIdRegistration()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime firstRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        using QuicConnectionRuntime secondRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionHandle secondHandle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.20",
            localAddress: "192.0.2.20",
            remotePort: 44331,
            localPort: 4433);

        Assert.True(endpoint.TryRegisterConnection(firstHandle, firstRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(firstHandle, registeredPath));
        Assert.True(endpoint.TryRegisterConnectionId(firstHandle, ReadOnlySpan<byte>.Empty));

        Assert.True(endpoint.TryRegisterConnection(secondHandle, secondRuntime));
        Assert.True(endpoint.TryUpdateEndpointBinding(secondHandle, registeredPath));
        Assert.False(endpoint.TryRegisterConnectionId(secondHandle, ReadOnlySpan<byte>.Empty));
    }
}
