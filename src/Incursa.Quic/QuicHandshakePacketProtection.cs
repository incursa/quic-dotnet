using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Provides Handshake packet protection using TLS-derived packet-protection material.
/// </summary>
internal sealed class QuicHandshakePacketProtection
{
    private const int AuthenticationTagLength = QuicInitialPacketProtection.AuthenticationTagLength;
    private const int AeadNonceLength = QuicInitialPacketProtection.AeadNonceLength;
    private const int HeaderProtectionSampleOffset = QuicInitialPacketProtection.HeaderProtectionSampleOffset;
    private const int HeaderProtectionSampleLength = QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int HeaderProtectionMaskLength = QuicInitialPacketProtection.HeaderProtectionSampleLength;

    private readonly QuicTlsPacketProtectionMaterial material;

    private QuicHandshakePacketProtection(QuicTlsPacketProtectionMaterial material)
    {
        this.material = material;
    }

    /// <summary>
    /// Creates a Handshake packet protector from TLS-derived packet-protection material.
    /// </summary>
    public static bool TryCreate(
        QuicTlsPacketProtectionMaterial? material,
        out QuicHandshakePacketProtection protection)
    {
        protection = default!;

        if (!material.HasValue)
        {
            return false;
        }

        QuicTlsPacketProtectionMaterial handshakeMaterial = material.Value;
        if (handshakeMaterial.EncryptionLevel != QuicTlsEncryptionLevel.Handshake)
        {
            return false;
        }

        if (!QuicAeadAlgorithmMetadata.TryGetPacketProtectionLengths(
            handshakeMaterial.Algorithm,
            out int expectedAeadKeyLength,
            out int expectedAeadIvLength,
            out int expectedHeaderProtectionKeyLength))
        {
            return false;
        }

        if (handshakeMaterial.AeadKey.Length != expectedAeadKeyLength
            || handshakeMaterial.AeadIv.Length != expectedAeadIvLength
            || handshakeMaterial.HeaderProtectionKey.Length != expectedHeaderProtectionKeyLength)
        {
            return false;
        }

        protection = new QuicHandshakePacketProtection(handshakeMaterial);
        return true;
    }

    /// <summary>
    /// Protects a Handshake packet using the stored Handshake material.
    /// </summary>
    public bool TryProtect(
        ReadOnlySpan<byte> plaintextPacket,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryParseHandshakePacketLayout(
            plaintextPacket,
            out byte headerControlBits,
            out ulong lengthFieldValue,
            out int packetNumberOffset))
        {
            return false;
        }

        if (!TryValidatePlaintextHandshakeHeader(headerControlBits))
        {
            return false;
        }

        int packetNumberLength = (headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        if (lengthFieldValue < (ulong)(packetNumberLength + AuthenticationTagLength)
            || lengthFieldValue > (ulong)(int.MaxValue - packetNumberOffset))
        {
            return false;
        }

        int plaintextPayloadLength = checked((int)lengthFieldValue) - packetNumberLength - AuthenticationTagLength;
        if (plaintextPacket.Length != packetNumberOffset + packetNumberLength + plaintextPayloadLength)
        {
            return false;
        }

        if (plaintextPayloadLength < HeaderProtectionSampleOffset + HeaderProtectionSampleLength)
        {
            return false;
        }

        int protectedPacketLength = packetNumberOffset + checked((int)lengthFieldValue);
        if (destination.Length < protectedPacketLength)
        {
            return false;
        }

        try
        {
            plaintextPacket[..(packetNumberOffset + packetNumberLength)].CopyTo(destination);

            Span<byte> nonce = stackalloc byte[AeadNonceLength];
            BuildNonce(
                material.AeadIvBytes,
                plaintextPacket.Slice(packetNumberOffset, packetNumberLength),
                nonce);

            if (!TryEncryptPacketPayload(
                nonce,
                plaintextPacket.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination.Slice(packetNumberOffset + packetNumberLength + plaintextPayloadLength, AuthenticationTagLength),
                destination[..(packetNumberOffset + packetNumberLength)]))
            {
                return false;
            }

            if (!TryApplyHeaderProtection(
                destination,
                packetNumberOffset,
                packetNumberLength))
            {
                return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        bytesWritten = protectedPacketLength;
        return true;
    }

    /// <summary>
    /// Opens a Handshake packet using the stored Handshake material.
    /// </summary>
    public bool TryOpen(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryParseHandshakePacketLayout(
            protectedPacket,
            out _,
            out ulong lengthFieldValue,
            out int packetNumberOffset))
        {
            return false;
        }

        if (lengthFieldValue < AuthenticationTagLength + 1
            || lengthFieldValue > (ulong)(int.MaxValue - packetNumberOffset)
            || protectedPacket.Length != packetNumberOffset + checked((int)lengthFieldValue))
        {
            return false;
        }

        if (protectedPacket.Length < packetNumberOffset + HeaderProtectionSampleOffset + HeaderProtectionSampleLength)
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!material.TryGenerateHeaderProtectionMask(
            protectedPacket.Slice(packetNumberOffset + HeaderProtectionSampleOffset, HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        byte unmaskedFirstByte = (byte)(protectedPacket[0] ^ (mask[0] & QuicPacketHeaderBits.TypeSpecificBitsMask));
        if ((unmaskedFirstByte & QuicPacketHeaderBits.HeaderFormBitMask) == 0
            || (unmaskedFirstByte & QuicPacketHeaderBits.FixedBitMask) == 0
            || ((unmaskedFirstByte & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift) != QuicLongPacketTypeBits.Handshake)
        {
            return false;
        }

        int packetNumberLength = (unmaskedFirstByte & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        if (lengthFieldValue < (ulong)(packetNumberLength + AuthenticationTagLength))
        {
            return false;
        }

        int plaintextPayloadLength = checked((int)lengthFieldValue) - packetNumberLength - AuthenticationTagLength;
        int unprotectedPacketLength = packetNumberOffset + packetNumberLength + plaintextPayloadLength;
        if (destination.Length < unprotectedPacketLength)
        {
            return false;
        }

        try
        {
            protectedPacket[..packetNumberOffset].CopyTo(destination);
            destination[0] = unmaskedFirstByte;

            for (int i = 0; i < packetNumberLength; i++)
            {
                destination[packetNumberOffset + i] = (byte)(protectedPacket[packetNumberOffset + i] ^ mask[1 + i]);
            }

            Span<byte> nonce = stackalloc byte[AeadNonceLength];
            BuildNonce(
                material.AeadIvBytes,
                destination.Slice(packetNumberOffset, packetNumberLength),
                nonce);

            if (!TryDecryptPacketPayload(
                nonce,
                protectedPacket.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                protectedPacket.Slice(packetNumberOffset + packetNumberLength + plaintextPayloadLength, AuthenticationTagLength),
                destination.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination[..(packetNumberOffset + packetNumberLength)]))
            {
                return false;
            }
        }
        catch (CryptographicException)
        {
            return false;
        }

        bytesWritten = unprotectedPacketLength;
        return true;
    }

    private static bool TryParseHandshakePacketLayout(
        ReadOnlySpan<byte> packet,
        out byte headerControlBits,
        out ulong lengthFieldValue,
        out int packetNumberOffset)
    {
        headerControlBits = default;
        lengthFieldValue = default;
        packetNumberOffset = default;

        if (!QuicPacketParsing.TryParseLongHeaderFields(
            packet,
            out headerControlBits,
            out uint version,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData)
            || version != 1)
        {
            return false;
        }

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out lengthFieldValue, out int lengthFieldBytes))
        {
            return false;
        }

        int versionSpecificDataOffset = packet.Length - versionSpecificData.Length;
        packetNumberOffset = versionSpecificDataOffset + lengthFieldBytes;
        return true;
    }

    private static bool TryValidatePlaintextHandshakeHeader(byte headerControlBits)
    {
        if ((headerControlBits & QuicPacketHeaderBits.FixedBitMask) == 0)
        {
            return false;
        }

        byte longPacketTypeBits = (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift);
        return longPacketTypeBits == QuicLongPacketTypeBits.Handshake;
    }

    private static void BuildNonce(ReadOnlySpan<byte> iv, ReadOnlySpan<byte> packetNumber, Span<byte> nonce)
    {
        iv.CopyTo(nonce);

        int nonceOffset = nonce.Length - packetNumber.Length;
        for (int i = 0; i < packetNumber.Length; i++)
        {
            nonce[nonceOffset + i] ^= packetNumber[i];
        }
    }

    private bool TryApplyHeaderProtection(
        Span<byte> packet,
        int packetNumberOffset,
        int packetNumberLength)
    {
        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!material.TryGenerateHeaderProtectionMask(
            packet.Slice(packetNumberOffset + HeaderProtectionSampleOffset, HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        packet[0] ^= (byte)(mask[0] & QuicPacketHeaderBits.TypeSpecificBitsMask);
        for (int i = 0; i < packetNumberLength; i++)
        {
            packet[packetNumberOffset + i] ^= mask[1 + i];
        }

        return true;
    }

    private bool TryEncryptPacketPayload(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        return material.TryEncryptPacketPayload(nonce, plaintext, ciphertext, tag, associatedData);
    }

    private bool TryDecryptPacketPayload(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        return material.TryDecryptPacketPayload(nonce, ciphertext, tag, plaintext, associatedData);
    }
}
