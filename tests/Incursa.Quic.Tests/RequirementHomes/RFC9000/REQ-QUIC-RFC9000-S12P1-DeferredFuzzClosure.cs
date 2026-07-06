// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S12P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S12P1-0005")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void InitialProtectionFuzz_RoundTripsFromClientInitialDcidAndLeavesConnectionIdsVisible()
    {
        for (int iteration = 0; iteration < 64; iteration++)
        {
            int destinationConnectionIdLength = 1 + (iteration % 20);
            int sourceConnectionIdLength = iteration % 9;
            int packetNumberLength = 1 + (iteration % 4);
            int payloadLength = 20 + (iteration % 17);
            byte[] clientInitialDcid = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x20 + iteration), destinationConnectionIdLength);
            byte[] sourceConnectionId = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x60 + iteration), sourceConnectionIdLength);
            byte[] packetNumber = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x90 + iteration), packetNumberLength);
            byte[] plaintextPayload = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0xA0 + iteration), payloadLength);

            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Client,
                clientInitialDcid,
                out QuicInitialPacketProtection clientProtection));
            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                clientInitialDcid,
                out QuicInitialPacketProtection serverProtection));

            byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
                clientInitialDcid,
                sourceConnectionId,
                token: [],
                packetNumber,
                plaintextPayload);
            byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];

            Assert.True(clientProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
            Assert.Equal(protectedPacket.Length, protectedBytesWritten);
            Assert.True(clientInitialDcid.AsSpan().SequenceEqual(protectedPacket.AsSpan(6, clientInitialDcid.Length)));
            Assert.True(sourceConnectionId.AsSpan().SequenceEqual(
                protectedPacket.AsSpan(7 + clientInitialDcid.Length, sourceConnectionId.Length)));

            byte[] openedPacket = new byte[plaintextPacket.Length];
            Assert.True(serverProtection.TryOpen(
                protectedPacket.AsSpan(0, protectedBytesWritten),
                openedPacket,
                out int openedBytesWritten));
            Assert.Equal(plaintextPacket.Length, openedBytesWritten);
            Assert.True(plaintextPacket.AsSpan().SequenceEqual(openedPacket));

            byte[] differentClientInitialDcid = clientInitialDcid.ToArray();
            differentClientInitialDcid[^1] ^= 0x7F;
            Assert.True(QuicInitialPacketProtection.TryCreate(
                QuicTlsRole.Server,
                differentClientInitialDcid,
                out QuicInitialPacketProtection wrongServerProtection));
            Assert.False(wrongServerProtection.TryOpen(
                protectedPacket.AsSpan(0, protectedBytesWritten),
                new byte[plaintextPacket.Length],
                out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S12P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void HandshakeProtectionFuzz_OnlyMatchingTlsMaterialCanOpenProtectedHandshakePackets()
    {
        for (int iteration = 0; iteration < 64; iteration++)
        {
            int packetNumberLength = 1 + (iteration % 4);
            byte[] destinationConnectionId = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x10 + iteration), 4 + (iteration % 8));
            byte[] sourceConnectionId = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x50 + iteration), iteration % 9);
            byte[] packetNumber = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0x70 + iteration), packetNumberLength);
            byte[] plaintextPayload = QuicS12P3TestSupport.CreateSequentialBytes((byte)(0xA0 + iteration), 20 + (iteration % 19));

            Assert.True(TryCreateHandshakeMaterial((byte)(0x11 + iteration), out QuicTlsPacketProtectionMaterial matchingMaterial));
            Assert.True(TryCreateHandshakeMaterial((byte)(0x41 + iteration), out QuicTlsPacketProtectionMaterial differentMaterial));
            Assert.True(QuicHandshakePacketProtection.TryCreate(matchingMaterial, out QuicHandshakePacketProtection senderProtection));
            Assert.True(QuicHandshakePacketProtection.TryCreate(matchingMaterial, out QuicHandshakePacketProtection receiverProtection));
            Assert.True(QuicHandshakePacketProtection.TryCreate(differentMaterial, out QuicHandshakePacketProtection wrongReceiverProtection));

            byte[] plaintextPacket = QuicHandshakePacketProtectionTestData.BuildHandshakePlaintextPacket(
                destinationConnectionId,
                sourceConnectionId,
                packetNumber,
                plaintextPayload);
            byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];

            Assert.True(senderProtection.TryProtect(plaintextPacket, protectedPacket, out int protectedBytesWritten));
            Assert.Equal(protectedPacket.Length, protectedBytesWritten);

            byte[] recoveredPacket = new byte[plaintextPacket.Length];
            Assert.True(receiverProtection.TryOpen(
                protectedPacket.AsSpan(0, protectedBytesWritten),
                recoveredPacket,
                out int recoveredBytesWritten));
            Assert.Equal(plaintextPacket.Length, recoveredBytesWritten);
            Assert.True(plaintextPacket.AsSpan().SequenceEqual(recoveredPacket));

            Assert.False(wrongReceiverProtection.TryOpen(
                protectedPacket.AsSpan(0, protectedBytesWritten),
                new byte[plaintextPacket.Length],
                out _));
        }
    }

    private static bool TryCreateHandshakeMaterial(byte secretStart, out QuicTlsPacketProtectionMaterial material)
    {
        return QuicTlsPacketProtectionMaterial.TryCreate(
            QuicTlsEncryptionLevel.Handshake,
            QuicAeadAlgorithm.Aes128Gcm,
            QuicS12P3TestSupport.CreateSequentialBytes(secretStart, 16),
            QuicS12P3TestSupport.CreateSequentialBytes((byte)(secretStart + 0x20), 12),
            QuicS12P3TestSupport.CreateSequentialBytes((byte)(secretStart + 0x40), 16),
            new QuicAeadUsageLimits(64, 128),
            out material);
    }
}
