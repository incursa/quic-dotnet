using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic;

/// <summary>
/// Provides Initial-only QUIC packet protection using the RFC 9001 fixed Initial salt and AES-128-GCM.
/// </summary>
internal sealed class QuicInitialPacketProtection
{
    /// <summary>
    /// The AEAD tag length used by AEAD_AES_128_GCM.
    /// </summary>
    public const int AuthenticationTagLength = 16;

    /// <summary>
    /// The AEAD key length used by AEAD_AES_128_GCM.
    /// </summary>
    public const int AeadKeyLength = 16;

    /// <summary>
    /// The AEAD nonce length used by AEAD_AES_128_GCM.
    /// </summary>
    public const int AeadNonceLength = 12;

    /// <summary>
    /// The header-protection key length used by AES-based QUIC header protection.
    /// </summary>
    public const int HeaderProtectionKeyLength = 16;

    /// <summary>
    /// The maximum length of the client Initial destination connection ID used for Initial key derivation.
    /// </summary>
    private const int MaximumInitialConnectionIdLength = 20;

    /// <summary>
    /// The number of bytes used to encode the HKDF length field.
    /// </summary>
    private const int HkdfLengthFieldLength = sizeof(ushort);

    /// <summary>
    /// The number of bytes used to encode the HKDF label length field.
    /// </summary>
    private const int HkdfLabelLengthFieldLength = 1;

    /// <summary>
    /// The number of bytes used to encode the HKDF context length field.
    /// </summary>
    private const int HkdfContextLengthFieldLength = 1;

    /// <summary>
    /// The length in bytes of a single HKDF-Expand block counter.
    /// </summary>
    private const int HkdfExpandCounterLength = 1;

    /// <summary>
    /// The block counter value used for the single-output HKDF-Expand-Label invocations in this slice.
    /// </summary>
    private const byte HkdfExpandCounterValue = 1;

    /// <summary>
    /// The offset from the start of the HKDF label to the ASCII prefix bytes.
    /// </summary>
    private const int HkdfPrefixOffset = HkdfLengthFieldLength + HkdfLabelLengthFieldLength;

    /// <summary>
    /// The number of bytes skipped before the ciphertext sample used for header protection.
    /// </summary>
    public const int HeaderProtectionSampleOffset = 4;

    /// <summary>
    /// The number of bytes sampled from the ciphertext for header protection.
    /// </summary>
    public const int HeaderProtectionSampleLength = 16;

    /// <summary>
    /// The Initial salt from RFC 9001 Section 5.2.
    /// </summary>
    private static readonly byte[] InitialSalt =
    [
        0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3,
        0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD,
        0xCC, 0xBB, 0x7F, 0x0A,
    ];

    private static readonly byte[] HkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] ClientInLabel = Encoding.ASCII.GetBytes("client in");
    private static readonly byte[] ServerInLabel = Encoding.ASCII.GetBytes("server in");
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");

    private readonly QuicTlsRole role;
    private readonly QuicInitialPacketProtectionMaterial clientMaterial;
    private readonly QuicInitialPacketProtectionMaterial serverMaterial;

    private QuicInitialPacketProtection(
        QuicTlsRole role,
        QuicInitialPacketProtectionMaterial clientMaterial,
        QuicInitialPacketProtectionMaterial serverMaterial)
    {
        this.role = role;
        this.clientMaterial = clientMaterial;
        this.serverMaterial = serverMaterial;
    }

    /// <summary>
    /// Gets the endpoint role that owns the helper.
    /// </summary>
    public QuicTlsRole Role => role;

    /// <summary>
    /// Gets the Initial material used for packets sent by the owning endpoint.
    /// </summary>
    public QuicInitialPacketProtectionMaterial OutboundMaterial => role == QuicTlsRole.Client
        ? clientMaterial
        : serverMaterial;

    /// <summary>
    /// Gets the Initial material used for packets received by the owning endpoint.
    /// </summary>
    public QuicInitialPacketProtectionMaterial InboundMaterial => role == QuicTlsRole.Client
        ? serverMaterial
        : clientMaterial;

    /// <summary>
    /// Creates a role-bound Initial packet protector from the first client Initial Destination Connection ID.
    /// </summary>
    public static bool TryCreate(
        QuicTlsRole role,
        ReadOnlySpan<byte> clientInitialDestinationConnectionId,
        out QuicInitialPacketProtection protection)
    {
        protection = default!;

        if (role is not QuicTlsRole.Client and not QuicTlsRole.Server)
        {
            return false;
        }

        if (!TryDeriveInitialKeyMaterial(
            clientInitialDestinationConnectionId,
            out QuicInitialPacketProtectionMaterial clientMaterial,
            out QuicInitialPacketProtectionMaterial serverMaterial))
        {
            return false;
        }

        protection = new QuicInitialPacketProtection(role, clientMaterial, serverMaterial);
        return true;
    }

    /// <summary>
    /// Derives the client and server Initial packet material from the first client Initial DCID.
    /// </summary>
    internal static bool TryDeriveInitialKeyMaterial(
        ReadOnlySpan<byte> clientInitialDestinationConnectionId,
        out QuicInitialPacketProtectionMaterial clientMaterial,
        out QuicInitialPacketProtectionMaterial serverMaterial)
    {
        clientMaterial = default;
        serverMaterial = default;

        if (clientInitialDestinationConnectionId.Length > MaximumInitialConnectionIdLength)
        {
            return false;
        }

        byte[] initialSecret = HkdfExtract(InitialSalt, clientInitialDestinationConnectionId);
        byte[] clientInitialSecret = HkdfExpandLabel(initialSecret, ClientInLabel, 32);
        byte[] serverInitialSecret = HkdfExpandLabel(initialSecret, ServerInLabel, 32);

        clientMaterial = DeriveInitialPacketProtectionMaterial(clientInitialSecret);
        serverMaterial = DeriveInitialPacketProtectionMaterial(serverInitialSecret);
        return true;
    }

    /// <summary>
    /// Protects an Initial packet using the role-appropriate Initial material.
    /// </summary>
    public bool TryProtect(
        ReadOnlySpan<byte> plaintextPacket,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryParseInitialPacketLayout(plaintextPacket, out byte headerControlBits, out ulong lengthFieldValue, out int packetNumberOffset))
        {
            return false;
        }

        if (!TryValidatePlaintextInitialHeader(headerControlBits))
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
            BuildNonce(OutboundMaterial.AeadIvBytes, plaintextPacket.Slice(packetNumberOffset, packetNumberLength), nonce);

            using AesGcm aead = new(OutboundMaterial.AeadKeyBytes, AuthenticationTagLength);
            aead.Encrypt(
                nonce,
                plaintextPacket.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination.Slice(packetNumberOffset + packetNumberLength + plaintextPayloadLength, AuthenticationTagLength),
                destination[..(packetNumberOffset + packetNumberLength)]);

            if (!TryApplyHeaderProtection(
                OutboundMaterial.HeaderProtectionKeyBytes,
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
    /// Opens an Initial packet using the role-appropriate Initial material.
    /// </summary>
    public bool TryOpen(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        out int bytesWritten)
    {
        return TryOpen(
            protectedPacket,
            destination,
            InboundMaterial,
            out bytesWritten);
    }

    /// <summary>
    /// Opens an outbound Initial packet using the owning endpoint's send keys.
    /// </summary>
    internal bool TryOpenOutbound(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        out int bytesWritten)
    {
        return TryOpen(
            protectedPacket,
            destination,
            OutboundMaterial,
            out bytesWritten);
    }

    private static bool TryOpen(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        QuicInitialPacketProtectionMaterial packetProtectionMaterial,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryParseInitialPacketLayout(protectedPacket, out _, out ulong lengthFieldValue, out int packetNumberOffset))
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

        Span<byte> mask = stackalloc byte[HeaderProtectionKeyLength];
        if (!TryGenerateHeaderProtectionMask(
            packetProtectionMaterial.HeaderProtectionKeyBytes,
            protectedPacket.Slice(packetNumberOffset + HeaderProtectionSampleOffset, HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        byte unmaskedFirstByte = (byte)(protectedPacket[0] ^ (mask[0] & QuicPacketHeaderBits.TypeSpecificBitsMask));
        if ((unmaskedFirstByte & QuicPacketHeaderBits.HeaderFormBitMask) == 0
            || (unmaskedFirstByte & QuicPacketHeaderBits.FixedBitMask) == 0
            || ((unmaskedFirstByte & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift) != QuicLongPacketTypeBits.Initial)
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
            BuildNonce(packetProtectionMaterial.AeadIvBytes, destination.Slice(packetNumberOffset, packetNumberLength), nonce);

            using AesGcm aead = new(packetProtectionMaterial.AeadKeyBytes, AuthenticationTagLength);
            aead.Decrypt(
                nonce,
                protectedPacket.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                protectedPacket.Slice(packetNumberOffset + packetNumberLength + plaintextPayloadLength, AuthenticationTagLength),
                destination.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination[..(packetNumberOffset + packetNumberLength)]);
        }
        catch (CryptographicException)
        {
            return false;
        }

        bytesWritten = unprotectedPacketLength;
        return true;
    }

    private static QuicInitialPacketProtectionMaterial DeriveInitialPacketProtectionMaterial(ReadOnlySpan<byte> secret)
    {
        byte[] aeadKey = HkdfExpandLabel(secret, QuicKeyLabel, AeadKeyLength);
        byte[] aeadIv = HkdfExpandLabel(secret, QuicIvLabel, AeadNonceLength);
        byte[] headerProtectionKey = HkdfExpandLabel(secret, QuicHpLabel, HeaderProtectionKeyLength);

        return new QuicInitialPacketProtectionMaterial(
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey);
    }

    private static bool TryParseInitialPacketLayout(
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

        if (!QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes))
        {
            return false;
        }

        if (tokenLength > (ulong)(versionSpecificData.Length - tokenLengthBytes))
        {
            return false;
        }

        ReadOnlySpan<byte> afterToken = versionSpecificData.Slice(tokenLengthBytes + (int)tokenLength);
        if (!QuicVariableLengthInteger.TryParse(afterToken, out lengthFieldValue, out int lengthFieldBytes))
        {
            return false;
        }

        int versionSpecificDataOffset = packet.Length - versionSpecificData.Length;
        packetNumberOffset = versionSpecificDataOffset + tokenLengthBytes + (int)tokenLength + lengthFieldBytes;
        return true;
    }

    private static bool TryValidatePlaintextInitialHeader(byte headerControlBits)
    {
        if ((headerControlBits & QuicPacketHeaderBits.FixedBitMask) == 0)
        {
            return false;
        }

        byte longPacketTypeBits = (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift);
        return longPacketTypeBits == QuicLongPacketTypeBits.Initial;
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

    private static bool TryApplyHeaderProtection(
        ReadOnlySpan<byte> headerProtectionKey,
        Span<byte> packet,
        int packetNumberOffset,
        int packetNumberLength)
    {
        Span<byte> mask = stackalloc byte[HeaderProtectionKeyLength];
        if (!TryGenerateHeaderProtectionMask(
            headerProtectionKey,
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

    private static bool TryGenerateHeaderProtectionMask(
        ReadOnlySpan<byte> headerProtectionKey,
        ReadOnlySpan<byte> sample,
        Span<byte> destination)
    {
        if (headerProtectionKey.Length != HeaderProtectionKeyLength
            || sample.Length < HeaderProtectionSampleLength
            || destination.Length < HeaderProtectionKeyLength)
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
                sample[..HeaderProtectionSampleLength],
                destination[..HeaderProtectionKeyLength],
                PaddingMode.None) == HeaderProtectionKeyLength;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static byte[] HkdfExtract(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> inputKeyMaterial)
    {
        using HMACSHA256 hmac = new(salt.ToArray());
        return hmac.ComputeHash(inputKeyMaterial.ToArray());
    }

    private static byte[] HkdfExpandLabel(ReadOnlySpan<byte> secret, ReadOnlySpan<byte> label, int length)
    {
        Span<byte> hkdfLabel = stackalloc byte[
            HkdfLengthFieldLength
            + HkdfLabelLengthFieldLength
            + HkdfLabelPrefix.Length
            + label.Length
            + HkdfContextLengthFieldLength];

        BinaryPrimitives.WriteUInt16BigEndian(hkdfLabel, checked((ushort)length));
        hkdfLabel[HkdfLengthFieldLength] = (byte)(HkdfLabelPrefix.Length + label.Length);
        HkdfLabelPrefix.CopyTo(hkdfLabel[HkdfPrefixOffset..]);
        label.CopyTo(hkdfLabel[(HkdfPrefixOffset + HkdfLabelPrefix.Length)..]);
        hkdfLabel[^1] = 0;

        byte[] expandInput = new byte[hkdfLabel.Length + HkdfExpandCounterLength];
        hkdfLabel.CopyTo(expandInput);
        expandInput[^1] = HkdfExpandCounterValue;

        using HMACSHA256 hmac = new(secret.ToArray());
        byte[] output = hmac.ComputeHash(expandInput);
        if (output.Length == length)
        {
            return output;
        }

        byte[] truncated = new byte[length];
        output.AsSpan(..length).CopyTo(truncated);
        return truncated;
    }
}

/// <summary>
/// Describes one role's Initial packet protection material.
/// </summary>
internal readonly struct QuicInitialPacketProtectionMaterial
{
    private readonly byte[] aeadKey;
    private readonly byte[] aeadIv;
    private readonly byte[] headerProtectionKey;

    internal QuicInitialPacketProtectionMaterial(
        QuicAeadAlgorithm algorithm,
        byte[] aeadKey,
        byte[] aeadIv,
        byte[] headerProtectionKey)
    {
        Algorithm = algorithm;
        this.aeadKey = aeadKey;
        this.aeadIv = aeadIv;
        this.headerProtectionKey = headerProtectionKey;
    }

    /// <summary>
    /// Gets the AEAD algorithm associated with this material.
    /// </summary>
    public QuicAeadAlgorithm Algorithm { get; }

    /// <summary>
    /// Gets the AEAD key.
    /// </summary>
    public ReadOnlySpan<byte> AeadKey => aeadKey;

    /// <summary>
    /// Gets the AEAD IV.
    /// </summary>
    public ReadOnlySpan<byte> AeadIv => aeadIv;

    /// <summary>
    /// Gets the header-protection key.
    /// </summary>
    public ReadOnlySpan<byte> HeaderProtectionKey => headerProtectionKey;

    internal byte[] AeadKeyBytes => aeadKey;

    internal byte[] AeadIvBytes => aeadIv;

    internal byte[] HeaderProtectionKeyBytes => headerProtectionKey;
}
