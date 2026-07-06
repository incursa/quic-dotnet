// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S17P2P2_NewIdDeferredFuzzClosure
{
    private static readonly byte[] InitialDestinationConnectionId =
    [
        0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08,
    ];

    private static readonly byte[] InitialSourceConnectionId =
    [
        0x01, 0x02, 0x03, 0x04,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0985")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ClientReceiptRejectsServerInitialPacketsWithNonZeroTokenLength()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        foreach (byte[] token in NonZeroTokenCorpus())
        {
            byte[] protectedPacket = BuildProtectedInitialPacket(token, senderProtection);

            QuicHandshakeFlowCoordinator coordinator = new();
            Assert.False(coordinator.TryOpenInitialPacket(
                protectedPacket,
                receiverProtection,
                requireZeroTokenLength: true,
                out _,
                out _,
                out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0985")]
    [Requirement("REQ-QUIC-RFC9000-0986")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ServerInitialPacketsWithZeroTokenLengthOpenForClientReceipt()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection senderProtection));
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            InitialDestinationConnectionId,
            out QuicInitialPacketProtection receiverProtection));

        foreach (byte[] cryptoPayload in CryptoPayloadCorpus())
        {
            QuicHandshakeFlowCoordinator coordinator = new(InitialDestinationConnectionId, InitialSourceConnectionId);
            Assert.True(coordinator.TryBuildProtectedInitialPacketForHandshakeDestination(
                cryptoPayload,
                cryptoPayloadOffset: 0,
                senderProtection,
                out byte[] protectedPacket));
            Assert.True(coordinator.TryOpenInitialPacket(
                protectedPacket,
                receiverProtection,
                requireZeroTokenLength: true,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            QuicS17P2P2TestSupport.AssertInitialTokenLength(openedPacket, 0UL);
            QuicS17P2P2TestSupport.AssertOpenedInitialPacketContainsCryptoPayload(
                openedPacket,
                payloadOffset,
                payloadLength,
                cryptoPayload,
                expectedCryptoOffset: 0UL);
        }
    }

    private static byte[] BuildProtectedInitialPacket(
        ReadOnlySpan<byte> token,
        QuicInitialPacketProtection senderProtection)
    {
        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            InitialDestinationConnectionId,
            InitialSourceConnectionId,
            token,
            packetNumber: [0x01],
            plaintextPayload: QuicS17P2P2TestSupport.CreateSequentialBytes(0x30, 24));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
        Assert.Equal(protectedPacket.Length, protectedBytesWritten);

        return protectedPacket;
    }

    private static IEnumerable<byte[]> NonZeroTokenCorpus()
    {
        int[] tokenLengths = [1, 2, 3, 15, 16, 31, 32, 63];
        foreach (int tokenLength in tokenLengths)
        {
            yield return QuicS17P2P2TestSupport.CreateSequentialBytes(0xA0, tokenLength);
        }

        Random random = new(0x1722);
        for (int i = 0; i < 32; i++)
        {
            yield return QuicHeaderTestData.RandomBytes(random, random.Next(1, 64));
        }
    }

    private static IEnumerable<byte[]> CryptoPayloadCorpus()
    {
        int[] payloadLengths = [1, 2, 7, 16, 24, 63, 64, 127];
        foreach (int payloadLength in payloadLengths)
        {
            yield return QuicS17P2P2TestSupport.CreateSequentialBytes(0x40, payloadLength);
        }

        Random random = new(0x1722_0002);
        for (int i = 0; i < 32; i++)
        {
            yield return QuicHeaderTestData.RandomBytes(random, random.Next(1, 128));
        }
    }
}
