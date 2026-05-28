// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0010")]
public sealed class REQ_QUIC_RFC9001_S4_0010
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketParserMapsPacketTypeToPacketNumberSpace()
    {
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            QuicRfc9001TailProofTestSupport.BuildMinimalInitialPacket(),
            out QuicPacketNumberSpace initialSpace));
        Assert.Equal(QuicPacketNumberSpace.Initial, initialSpace);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            QuicRfc9001TailProofTestSupport.BuildMinimalHandshakePacket(),
            out QuicPacketNumberSpace handshakeSpace));
        Assert.Equal(QuicPacketNumberSpace.Handshake, handshakeSpace);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(
            QuicRfc9001TailProofTestSupport.BuildMinimalOneRttPacket(),
            out QuicPacketNumberSpace oneRttSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, oneRttSpace);
    }
}
