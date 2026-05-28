// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0024")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0024
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedInitialPacket_EmitsACryptoFrameInTheInitialPayload()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        byte[] cryptoPayload = QuicS17P2P2TestSupport.CreateSequentialBytes(0x40, 16);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out byte[] protectedPacket));
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            serverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            openedPacket,
            payloadOffset,
            payloadLength,
            cryptoPayload,
            expectedCryptoOffset: 0);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InitialPingPayloadDoesNotSatisfyTheCryptoOrAckPayloadShape()
    {
        byte[] pingPayload = QuicFrameTestData.BuildPingFrame();

        Assert.False(QuicFrameCodec.TryParseCryptoFrame(pingPayload, out _, out _));
        Assert.False(QuicFrameCodec.TryParseAckFrame(pingPayload, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedInitialPacket_CanCarryAckBeforeCryptoInTheInitialPayload()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        byte[] ackPayload = QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
        });
        byte[] cryptoPayload = QuicS17P2P2TestSupport.CreateSequentialBytes(0x50, 8);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            ackPayload,
            clientProtection,
            out byte[] protectedPacket));
        Assert.True(coordinator.TryOpenInitialPacket(
            protectedPacket,
            serverProtection,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseAckFrame(payload, out QuicAckFrame ackFrame, out int ackBytesConsumed));
        Assert.Equal(0UL, ackFrame.LargestAcknowledged);
        QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
            openedPacket,
            payloadOffset + ackBytesConsumed,
            payloadLength - ackBytesConsumed,
            cryptoPayload,
            expectedCryptoOffset: 0);
    }
}
