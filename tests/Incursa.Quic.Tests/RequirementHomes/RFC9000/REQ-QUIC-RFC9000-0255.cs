// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0255")]
public sealed class REQ_QUIC_RFC9000_0255
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointProcessesZeroLengthConnectionIdPacketWhenLocalAddressMatches()
    {
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity();
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([]),
            registeredPath);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EndpointDoesNotProcessZeroLengthConnectionIdPacketWhenLocalAddressDiffers()
    {
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity();
        QuicConnectionPathIdentity mismatchedLocalAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            localAddress: "192.0.2.11");
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([]),
            mismatchedLocalAddress);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void EndpointProcessesZeroLengthConnectionIdPacketAcrossRemoteAddressChangeWhenLocalAddressMatches()
    {
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity();
        QuicConnectionPathIdentity changedRemoteAddress = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.99",
            remotePort: 44331);
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([]),
            changedRemoteAddress);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }
}
