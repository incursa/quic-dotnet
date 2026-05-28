// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P2-0026")]
public sealed class REQ_QUIC_RFC9000_S17P2P2_0026
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryBuildProtectedInitialPacket_FirstClientPacketCarriesOffsetZeroCryptoFrame()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        byte[] cryptoPayload = QuicS17P2P2TestSupport.CreateSequentialBytes(0x70, 20);
        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset: 0,
            clientProtection,
            out ulong packetNumber,
            out byte[] protectedPacket));
        Assert.Equal(0UL, packetNumber);
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
    public void TryBuildProtectedInitialPacket_DoesNotCreateTheFirstClientPacketWithoutCryptoData()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.False(coordinator.TryBuildProtectedInitialPacket(
            ReadOnlySpan<byte>.Empty,
            cryptoPayloadOffset: 0,
            clientProtection,
            out _,
            out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryBuildProtectedInitialPacket_AllowsAOneByteInitialCryptoStart()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection clientProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P2TestSupport.InitialDestinationConnectionId,
            out QuicInitialPacketProtection serverProtection));

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P2TestSupport.CreateClientCoordinator();
        Assert.True(coordinator.TryBuildProtectedInitialPacket(
            [0x01],
            cryptoPayloadOffset: 0,
            clientProtection,
            out ulong packetNumber,
            out byte[] protectedPacket));
        Assert.Equal(0UL, packetNumber);
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
            [0x01],
            expectedCryptoOffset: 0);
    }
}
