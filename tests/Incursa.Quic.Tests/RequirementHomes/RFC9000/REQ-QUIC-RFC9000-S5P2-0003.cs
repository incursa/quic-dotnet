// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P2-0003")]
public sealed class REQ_QUIC_RFC9000_S5P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void EndpointTriesExistingConnectionAssociationBeforeUnroutableHandling()
    {
        var scenario = QuicS5P2PacketAssociationTestSupport.CreateRegisteredEndpoint(
            QuicS5P2PacketAssociationTestSupport.RouteConnectionId);
        using QuicConnectionRuntime runtime = scenario.Runtime;
        using QuicConnectionRuntimeEndpoint endpoint = scenario.Endpoint;

        QuicConnectionIngressResult matched = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram(QuicS5P2PacketAssociationTestSupport.RouteConnectionId),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());
        QuicConnectionIngressResult unmatched = endpoint.ReceiveDatagram(
            QuicS5P2PacketAssociationTestSupport.BuildHandshakeDatagram([0x40, 0x41]),
            QuicS5P2P2ServerPreAcceptanceTestSupport.CreatePathIdentity());

        Assert.Equal(QuicConnectionIngressDisposition.RoutedToConnection, matched.Disposition);
        Assert.Equal(scenario.Handle, matched.Handle);
        Assert.Equal(QuicConnectionIngressDisposition.Unroutable, unmatched.Disposition);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryGetPacketNumberSpace_RecognizesHandshakePacketsThatCanBeAssociatedWithConnections()
    {
        byte[] packet = QuicHandshakePacketRequirementTestData.BuildHandshakePacket();

        Assert.True(QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket header));
        Assert.Equal((byte)0x02, header.LongPacketTypeBits);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, packetNumberSpace);
    }
}
