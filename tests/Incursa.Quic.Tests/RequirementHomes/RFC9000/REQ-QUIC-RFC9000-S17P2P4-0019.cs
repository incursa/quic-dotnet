// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S17P2P4-0019">The payload of this packet MUST contain CRYPTO frames and could contain PING, PADDING, or ACK frames.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S17P2P4-0019")]
public sealed class REQ_QUIC_RFC9000_S17P2P4_0019
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void HandshakePacketsCanCarryCryptoPingAndPaddingFrames()
    {
        Assert.True(QuicS12P3TestSupport.TryCreatePacketProtectionMaterial(
            QuicTlsEncryptionLevel.Handshake,
            out QuicTlsPacketProtectionMaterial material));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P1TestSupport.CreateHandshakeCoordinator();
        byte[] cryptoPayload = [0xAA, 0xAB];
        byte[] prefixFramePayload =
        [
            .. QuicFrameTestData.BuildPingFrame(),
            .. QuicFrameTestData.BuildPaddingFrame(),
        ];

        Assert.True(coordinator.TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            prefixFramePayload,
            material,
            out byte[] protectedPacket));

        Assert.True(coordinator.TryOpenHandshakePacket(
            protectedPacket,
            material,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParsePingFrame(payload, out int pingBytesConsumed));
        ReadOnlySpan<byte> remaining = QuicS13AckPiggybackTestSupport.SkipPadding(payload[pingBytesConsumed..]);
        Assert.True(QuicFrameCodec.TryParseCryptoFrame(remaining, out QuicCryptoFrame cryptoFrame, out int cryptoBytesConsumed));
        Assert.Equal(0UL, cryptoFrame.Offset);
        Assert.True(cryptoFrame.CryptoData.SequenceEqual(cryptoPayload));
        Assert.True(QuicS13AckPiggybackTestSupport.SkipPadding(remaining[cryptoBytesConsumed..]).IsEmpty);
    }
}
