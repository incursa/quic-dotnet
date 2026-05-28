// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0006")]
public sealed class REQ_QUIC_RFC9000_S5P2_0006
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ZeroLengthConnectionIdMatchingFailsWhenDestinationEndpointChanges()
    {
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity();
        QuicConnectionPathIdentity changedLocalEndpoint = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            localAddress: "192.0.2.11",
            localPort: 4444);
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([]),
            changedLocalEndpoint);

        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, result.Disposition);
        Assert.Null(result.Handle);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ZeroLengthConnectionIdMatchingCanUseDestinationEndpointOnly()
    {
        QuicConnectionPathIdentity registeredPath = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity();
        QuicConnectionPathIdentity changedRemoteEndpoint = QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity(
            remoteAddress: "203.0.113.99",
            remotePort: 44331);
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            ReadOnlySpan<byte>.Empty,
            registeredPath);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult result = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildShortHeaderDatagram([]),
            changedRemoteEndpoint);

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, result.Disposition);
        Assert.Equal(scenario.Handle, result.Handle);
    }
}
