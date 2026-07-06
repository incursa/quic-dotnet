// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2P2-0005")]
public sealed class REQ_QUIC_RFC9000_S5P2P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointMatchesSupportedVersionPacketsByDestinationConnectionId()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        byte[] routeId = [0x30, 0x31];

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, routeId));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram(routeId),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointLeavesSupportedVersionPacketsUnmatchedWhenTheConnectionIdIsUnknown()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryRegisterConnectionId(handle, [0x30, 0x31]));

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram([0x40, 0x41]),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointMatchesZeroLengthConnectionIdPacketsByLocalAddressAndPort()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(1);
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.20",
            localAddress: "192.0.2.20",
            remotePort: 44331,
            localPort: 4433);
        QuicConnectionPathIdentity matchingLocalAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.21",
            localAddress: "192.0.2.20",
            remotePort: 44332,
            localPort: 4433);
        QuicConnectionPathIdentity mismatchedLocalAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.21",
            localAddress: "192.0.2.21",
            remotePort: 44332,
            localPort: 4433);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, registeredPath));
        Assert.True(endpoint.TryRegisterConnectionId(handle, ReadOnlySpan<byte>.Empty));

        QuicConnectionIngressResult matched = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(),
            matchingLocalAddress);
        QuicConnectionIngressResult unmatched = endpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(),
            mismatchedLocalAddress);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matched.Disposition);
        Assert.Equal(handle, matched.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unmatched.Disposition);
        Assert.Null(unmatched.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void EndpointFuzzMatchesSupportedVersionPacketsByConnectionIdOrLocalAddressTuple()
    {
        byte[][] routeIds =
        [
            [0x30],
            [0x30, 0x31],
            [0x30, 0x31, 0x32, 0x33],
        ];

        foreach (byte[] routeId in routeIds)
        {
            using QuicConnectionRuntimeEndpoint endpoint = new(1);
            using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();

            Assert.True(endpoint.TryRegisterConnection(handle, runtime));
            Assert.True(endpoint.TryRegisterConnectionId(handle, routeId));

            QuicConnectionIngressResult matched = endpoint.ReceiveDatagram(
                QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram(routeId),
                QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());
            byte[] unknownRouteId = routeId.ToArray();
            unknownRouteId[^1] ^= 0x7F;
            QuicConnectionIngressResult unmatched = endpoint.ReceiveDatagram(
                QuicS5P2P2ServerPreAcceptanceTestSupport.BuildVersion1HandshakeDatagram(unknownRouteId),
                QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

            Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matched.Disposition);
            Assert.Equal(handle, matched.Handle);
            Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unmatched.Disposition);
            Assert.Null(unmatched.Handle);
        }

        using QuicConnectionRuntimeEndpoint zeroLengthEndpoint = new(1);
        using QuicConnectionRuntime zeroLengthRuntime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle zeroLengthHandle = zeroLengthEndpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.20",
            localAddress: "192.0.2.20",
            remotePort: 44331,
            localPort: 4433);
        QuicConnectionPathIdentity matchingLocalAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.21",
            localAddress: "192.0.2.20",
            remotePort: 44332,
            localPort: 4433);

        Assert.True(zeroLengthEndpoint.TryRegisterConnection(zeroLengthHandle, zeroLengthRuntime));
        Assert.True(zeroLengthEndpoint.TryUpdateEndpointBinding(zeroLengthHandle, registeredPath));
        Assert.True(zeroLengthEndpoint.TryRegisterConnectionId(zeroLengthHandle, ReadOnlySpan<byte>.Empty));

        QuicConnectionIngressResult zeroLengthMatched = zeroLengthEndpoint.ReceiveDatagram(
            QuicS5P2P2ServerPreAcceptanceTestSupport.BuildShortHeaderDatagram(),
            matchingLocalAddress);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, zeroLengthMatched.Disposition);
        Assert.Equal(zeroLengthHandle, zeroLengthMatched.Handle);
    }
}
