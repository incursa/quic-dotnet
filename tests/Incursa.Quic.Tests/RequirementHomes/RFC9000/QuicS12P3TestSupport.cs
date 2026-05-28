// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

internal static class QuicS12P3TestSupport
{
    internal static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int i = 0; i < length; i++)
        {
            bytes[i] = unchecked((byte)(startValue + i));
        }

        return bytes;
    }

    internal static byte[] CreatePingPayload()
    {
        byte[] payload = new byte[1];
        Assert.True(QuicFrameCodec.TryFormatPingFrame(payload, out int bytesWritten));
        Assert.Equal(1, bytesWritten);
        return payload;
    }

    internal static void AssertInitialAndHandshakeRecoveryPackets(
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        out ReadOnlyMemory<byte> initialPacket,
        out ReadOnlyMemory<byte> handshakePacket)
    {
        initialPacket = default;
        handshakePacket = default;

        foreach (QuicConnectionSendDatagramEffect sendEffect in sendEffects)
        {
            ReadOnlyMemory<byte> datagram = sendEffect.Datagram;
            if (TrySplitCoalescedDatagram(datagram, out ReadOnlyMemory<byte> coalescedInitialPacket, out ReadOnlyMemory<byte> coalescedHandshakePacket))
            {
                initialPacket = coalescedInitialPacket;
                handshakePacket = coalescedHandshakePacket;
                return;
            }

            if (!QuicPacketParser.TryGetPacketNumberSpace(datagram.Span, out QuicPacketNumberSpace packetNumberSpace))
            {
                continue;
            }

            if (packetNumberSpace == QuicPacketNumberSpace.Initial && initialPacket.IsEmpty)
            {
                initialPacket = datagram;
                continue;
            }

            if (packetNumberSpace == QuicPacketNumberSpace.Handshake && handshakePacket.IsEmpty)
            {
                handshakePacket = datagram;
            }
        }

        Assert.False(initialPacket.IsEmpty, "Expected a recovery probe in the Initial packet number space.");
        Assert.False(handshakePacket.IsEmpty, "Expected a recovery probe in the Handshake packet number space.");
    }

    internal static bool TryCreatePacketProtectionMaterial(
        QuicTlsEncryptionLevel encryptionLevel,
        out QuicTlsPacketProtectionMaterial material)
    {
        return QuicTlsPacketProtectionMaterial.TryCreate(
            encryptionLevel,
            QuicAeadAlgorithm.Aes128Gcm,
            CreateSequentialBytes(0x11, 16),
            CreateSequentialBytes(0x21, 12),
            CreateSequentialBytes(0x31, 16),
            new QuicAeadUsageLimits(64, 128),
            out material);
    }

    private static bool TrySplitCoalescedDatagram(
        ReadOnlyMemory<byte> datagram,
        out ReadOnlyMemory<byte> initialPacket,
        out ReadOnlyMemory<byte> handshakePacket)
    {
        initialPacket = default;
        handshakePacket = default;

        if (!QuicPacketParser.TryGetPacketLength(datagram.Span, out int initialPacketLength))
        {
            return false;
        }

        initialPacket = datagram[..initialPacketLength];
        handshakePacket = datagram[initialPacketLength..];
        return handshakePacket.Length > 0;
    }
}
