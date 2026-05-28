// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P6-0002")]
public sealed class REQ_QUIC_RFC9000_S19P6_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseCryptoFrame_CarriesHandshakeMessagesInAllowedPacketContexts()
    {
        byte[] payload = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(0, [0xAA, 0xBB]));

        byte[] initialPacket = QuicS17P2P2TestSupport.BuildInitialPacket(protectedPayload: payload);
        AssertPacketSpaceCarriesPayload(initialPacket, QuicPacketNumberSpace.Initial, payload);

        byte[] handshakePacket = QuicHandshakePacketRequirementTestData.BuildHandshakePacket(protectedPayload: payload);
        AssertPacketSpaceCarriesPayload(handshakePacket, QuicPacketNumberSpace.Handshake, payload);

        byte[] applicationPacket = QuicHeaderTestData.BuildShortHeader(0x00, payload);
        AssertPacketSpaceCarriesPayload(applicationPacket, QuicPacketNumberSpace.ApplicationData, payload);
    }

    private static void AssertPacketSpaceCarriesPayload(
        ReadOnlySpan<byte> packet,
        QuicPacketNumberSpace expectedPacketNumberSpace,
        ReadOnlySpan<byte> payload)
    {
        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(packet, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(expectedPacketNumberSpace, packetNumberSpace);
        Assert.True(packet[^payload.Length..].SequenceEqual(payload));
        QuicS19P6CryptoFrameTestSupport.AssertParses(payload, 0, [0xAA, 0xBB]);
    }
}
