using System.Security.Cryptography;

namespace Incursa.Quic.Tests;

internal static class QuicS17P3P1TestSupport
{
    internal static byte[] CreateProtectedApplicationDataPacket(
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> packetNumberBytes,
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        int declaredPacketNumberLength)
    {
        int packetNumberLength = packetNumberBytes.Length;
        Assert.InRange(packetNumberLength, 1, 4);
        Assert.InRange(declaredPacketNumberLength, 1, 4);

        int paddedPayloadLength = Math.Max(
            applicationPayload.Length,
            QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength);
        int packetNumberOffset = 1 + destinationConnectionId.Length;

        byte[] plaintextPacket = new byte[packetNumberOffset + packetNumberLength + paddedPayloadLength];
        plaintextPacket[0] = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | ((declaredPacketNumberLength - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask));
        destinationConnectionId.CopyTo(plaintextPacket.AsSpan(1));
        packetNumberBytes.CopyTo(plaintextPacket.AsSpan(packetNumberOffset));
        applicationPayload.CopyTo(plaintextPacket.AsSpan(packetNumberOffset + packetNumberLength));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        plaintextPacket[..(packetNumberOffset + packetNumberLength)].CopyTo(protectedPacket);

        Span<byte> nonce = stackalloc byte[QuicInitialPacketProtection.AeadNonceLength];
        BuildNonce(
            material.AeadIvBytes,
            plaintextPacket,
            packetNumberOffset,
            packetNumberLength,
            nonce);

        Assert.True(TryEncryptPacketPayload(
            material,
            nonce,
            plaintextPacket.AsSpan(packetNumberOffset + packetNumberLength, paddedPayloadLength),
            protectedPacket.AsSpan(packetNumberOffset + packetNumberLength, paddedPayloadLength),
            protectedPacket.AsSpan(plaintextPacket.Length, QuicInitialPacketProtection.AuthenticationTagLength),
            protectedPacket.AsSpan(0, packetNumberOffset + packetNumberLength)));

        Assert.True(TryApplyHeaderProtection(
            material,
            protectedPacket,
            packetNumberOffset,
            packetNumberLength));

        return protectedPacket;
    }

    private static void BuildNonce(
        ReadOnlySpan<byte> iv,
        ReadOnlySpan<byte> packet,
        int packetNumberOffset,
        int packetNumberLength,
        Span<byte> nonce)
    {
        iv.CopyTo(nonce);

        int nonceOffset = nonce.Length - packetNumberLength;
        for (int index = 0; index < packetNumberLength; index++)
        {
            nonce[nonceOffset + index] ^= packet[packetNumberOffset + index];
        }
    }

    private static bool TryEncryptPacketPayload(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        switch (material.Algorithm)
        {
            case QuicAeadAlgorithm.Aes128Gcm:
            case QuicAeadAlgorithm.Aes256Gcm:
                using (AesGcm aeadGcm = new(material.AeadKeyBytes, QuicInitialPacketProtection.AuthenticationTagLength))
                {
                    aeadGcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                }

                return true;

            case QuicAeadAlgorithm.Aes128Ccm:
                using (AesCcm aeadCcm = new(material.AeadKeyBytes))
                {
                    aeadCcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
                }

                return true;

            default:
                return false;
        }
    }

    private static bool TryApplyHeaderProtection(
        QuicTlsPacketProtectionMaterial material,
        Span<byte> packet,
        int packetNumberOffset,
        int packetNumberLength)
    {
        Span<byte> mask = stackalloc byte[QuicInitialPacketProtection.HeaderProtectionSampleLength];
        if (!TryGenerateHeaderProtectionMask(
            material.HeaderProtectionKeyBytes,
            packet.Slice(packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset, QuicInitialPacketProtection.HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        packet[0] ^= (byte)(mask[0] & QuicPacketHeaderBits.TypeSpecificBitsMask);
        for (int index = 0; index < packetNumberLength; index++)
        {
            packet[packetNumberOffset + index] ^= mask[1 + index];
        }

        return true;
    }

    private static bool TryGenerateHeaderProtectionMask(
        ReadOnlySpan<byte> headerProtectionKey,
        ReadOnlySpan<byte> sample,
        Span<byte> destination)
    {
        if (sample.Length < QuicInitialPacketProtection.HeaderProtectionSampleLength
            || destination.Length < QuicInitialPacketProtection.HeaderProtectionSampleLength)
        {
            return false;
        }

        try
        {
            using Aes aes = Aes.Create();
            aes.Key = headerProtectionKey.ToArray();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            return aes.EncryptEcb(
                sample[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                destination[..QuicInitialPacketProtection.HeaderProtectionSampleLength],
                PaddingMode.None) == QuicInitialPacketProtection.HeaderProtectionSampleLength;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }
}
