using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Incursa.Quic;

/// <summary>
/// Provides Initial packet protection for the supported QUIC transport versions using the version-specific
/// Initial salt and AES-128-GCM.
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
    private static readonly byte[] InitialSaltV1 =
    [
        0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3,
        0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD,
        0xCC, 0xBB, 0x7F, 0x0A,
    ];

    /// <summary>
    /// The Initial salt from RFC 9369 Section 7.
    /// </summary>
    private static readonly byte[] InitialSaltV2 =
    [
        0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB,
        0x81, 0x93, 0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB,
        0xF9, 0xBD, 0x2E, 0xD9,
    ];

    private static readonly byte[] HkdfLabelPrefix = Encoding.ASCII.GetBytes("tls13 ");
    private static readonly byte[] ClientInLabel = Encoding.ASCII.GetBytes("client in");
    private static readonly byte[] ServerInLabel = Encoding.ASCII.GetBytes("server in");
    private static readonly byte[] QuicKeyLabel = Encoding.ASCII.GetBytes("quic key");
    private static readonly byte[] QuicIvLabel = Encoding.ASCII.GetBytes("quic iv");
    private static readonly byte[] QuicHpLabel = Encoding.ASCII.GetBytes("quic hp");
    private static readonly byte[] QuicV2KeyLabel = Encoding.ASCII.GetBytes("quicv2 key");
    private static readonly byte[] QuicV2IvLabel = Encoding.ASCII.GetBytes("quicv2 iv");
    private static readonly byte[] QuicV2HpLabel = Encoding.ASCII.GetBytes("quicv2 hp");

    private readonly QuicTlsRole role;
    private readonly uint version;
    private readonly QuicInitialPacketProtectionMaterial clientMaterial;
    private readonly QuicInitialPacketProtectionMaterial serverMaterial;

    private QuicInitialPacketProtection(
        QuicTlsRole role,
        uint version,
        QuicInitialPacketProtectionMaterial clientMaterial,
        QuicInitialPacketProtectionMaterial serverMaterial)
    {
        this.role = role;
        this.version = version;
        this.clientMaterial = clientMaterial;
        this.serverMaterial = serverMaterial;
    }

    /// <summary>
    /// Gets the endpoint role that owns the helper.
    /// </summary>
    public QuicTlsRole Role => role;

    /// <summary>
    /// Gets the transport version this protector was derived for.
    /// </summary>
    internal uint Version => version;

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
        => TryCreate(role, QuicVersionNegotiation.Version1, clientInitialDestinationConnectionId, out protection);

    /// <summary>
    /// Creates a role-bound Initial packet protector from the first client Initial Destination Connection ID.
    /// </summary>
    public static bool TryCreate(
        QuicTlsRole role,
        uint version,
        ReadOnlySpan<byte> clientInitialDestinationConnectionId,
        out QuicInitialPacketProtection protection)
    {
        protection = default!;

        if (role is not QuicTlsRole.Client and not QuicTlsRole.Server)
        {
            return false;
        }

        if (!QuicVersionNegotiation.IsSupportedTransportVersion(version))
        {
            return false;
        }

        if (!TryDeriveInitialKeyMaterial(
            version,
            clientInitialDestinationConnectionId,
            out QuicInitialPacketProtectionMaterial clientMaterial,
            out QuicInitialPacketProtectionMaterial serverMaterial))
        {
            return false;
        }

        protection = new QuicInitialPacketProtection(role, version, clientMaterial, serverMaterial);
        return true;
    }

    /// <summary>
    /// Derives the client and server Initial packet material from the first client Initial DCID.
    /// </summary>
    internal static bool TryDeriveInitialKeyMaterial(
        ReadOnlySpan<byte> clientInitialDestinationConnectionId,
        out QuicInitialPacketProtectionMaterial clientMaterial,
        out QuicInitialPacketProtectionMaterial serverMaterial)
        => TryDeriveInitialKeyMaterial(
            QuicVersionNegotiation.Version1,
            clientInitialDestinationConnectionId,
            out clientMaterial,
            out serverMaterial);

    /// <summary>
    /// Derives the client and server Initial packet material from the first client Initial DCID.
    /// </summary>
    internal static bool TryDeriveInitialKeyMaterial(
        uint version,
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

        byte[] initialSecret = HkdfExtract(GetInitialSalt(version), clientInitialDestinationConnectionId);
        byte[] clientInitialSecret = HkdfExpandLabel(initialSecret, ClientInLabel, 32);
        byte[] serverInitialSecret = HkdfExpandLabel(initialSecret, ServerInLabel, 32);

        try
        {
            clientMaterial = DeriveInitialPacketProtectionMaterial(version, clientInitialSecret);
            serverMaterial = DeriveInitialPacketProtectionMaterial(version, serverInitialSecret);
            return true;
        }
        catch (CryptographicException)
        {
            clientMaterial = default;
            serverMaterial = default;
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            clientMaterial = default;
            serverMaterial = default;
            return false;
        }
    }

    /// <summary>
    /// Protects an Initial packet using the role-appropriate Initial material.
    /// </summary>
    public bool TryProtect(
        ReadOnlySpan<byte> plaintextPacket,
        Span<byte> destination,
        out int bytesWritten)
    {
        return TryProtect(
            plaintextPacket,
            destination,
            allowClearedFixedBit: false,
            out bytesWritten);
    }

    /// <summary>
    /// Protects an Initial packet using the role-appropriate Initial material.
    /// </summary>
    public bool TryProtect(
        ReadOnlySpan<byte> plaintextPacket,
        Span<byte> destination,
        bool allowClearedFixedBit,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryParseInitialPacketLayout(
            plaintextPacket,
            out uint packetVersion,
            out byte headerControlBits,
            out ulong lengthFieldValue,
            out int packetNumberOffset)
            || packetVersion != version)
        {
            return false;
        }

        if (!TryValidatePlaintextInitialHeader(packetVersion, headerControlBits, allowClearedFixedBit))
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

            if (!OutboundMaterial.TryEncryptPacketPayload(
                nonce,
                plaintextPacket.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                destination.Slice(packetNumberOffset + packetNumberLength + plaintextPayloadLength, AuthenticationTagLength),
                destination[..(packetNumberOffset + packetNumberLength)]))
            {
                return false;
            }

            if (!TryApplyHeaderProtection(
                OutboundMaterial,
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
            allowClearedFixedBit: false,
            out bytesWritten);
    }

    /// <summary>
    /// Opens an Initial packet using the role-appropriate Initial material.
    /// </summary>
    public bool TryOpen(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        bool allowClearedFixedBit,
        out int bytesWritten)
    {
        return TryOpen(
            protectedPacket,
            destination,
            version,
            InboundMaterial,
            allowClearedFixedBit,
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
            version,
            OutboundMaterial,
            false,
            out bytesWritten);
    }

    /// <summary>
    /// Opens an outbound Initial packet using the owning endpoint's send keys.
    /// </summary>
    internal bool TryOpenOutbound(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        bool allowClearedFixedBit,
        out int bytesWritten)
    {
        return TryOpen(
            protectedPacket,
            destination,
            version,
            OutboundMaterial,
            allowClearedFixedBit,
            out bytesWritten);
    }

    private static bool TryOpen(
        ReadOnlySpan<byte> protectedPacket,
        Span<byte> destination,
        uint expectedVersion,
        QuicInitialPacketProtectionMaterial packetProtectionMaterial,
        bool allowClearedFixedBit,
        out int bytesWritten)
    {
        bytesWritten = default;

        if (!TryParseInitialPacketLayout(
            protectedPacket,
            out uint packetVersion,
            out _,
            out ulong lengthFieldValue,
            out int packetNumberOffset)
            || packetVersion != expectedVersion)
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
        if (!packetProtectionMaterial.TryGenerateHeaderProtectionMask(
            protectedPacket.Slice(packetNumberOffset + HeaderProtectionSampleOffset, HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        byte unmaskedFirstByte = (byte)(protectedPacket[0] ^ (mask[0] & QuicPacketHeaderBits.TypeSpecificBitsMask));
        if (!TryValidatePlaintextInitialHeader(
            packetVersion,
            unmaskedFirstByte,
            allowClearedFixedBit))
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

            if (!packetProtectionMaterial.TryDecryptPacketPayload(
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

    private static QuicInitialPacketProtectionMaterial DeriveInitialPacketProtectionMaterial(uint version, ReadOnlySpan<byte> secret)
    {
        byte[] aeadKey = HkdfExpandLabel(secret, GetInitialKeyLabel(version), AeadKeyLength);
        byte[] aeadIv = HkdfExpandLabel(secret, GetInitialIvLabel(version), AeadNonceLength);
        byte[] headerProtectionKey = HkdfExpandLabel(secret, GetInitialHeaderProtectionLabel(version), HeaderProtectionKeyLength);

        return new QuicInitialPacketProtectionMaterial(
            QuicAeadAlgorithm.Aes128Gcm,
            aeadKey,
            aeadIv,
            headerProtectionKey);
    }

    private static bool TryParseInitialPacketLayout(
        ReadOnlySpan<byte> packet,
        out uint packetVersion,
        out byte headerControlBits,
        out ulong lengthFieldValue,
        out int packetNumberOffset)
    {
        packetVersion = default;
        headerControlBits = default;
        lengthFieldValue = default;
        packetNumberOffset = default;

        if (!QuicPacketParsing.TryParseLongHeaderFields(
            packet,
            out headerControlBits,
            out packetVersion,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData)
            || !QuicVersionNegotiation.IsSupportedTransportVersion(packetVersion))
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

    private static bool TryValidatePlaintextInitialHeader(uint packetVersion, byte headerControlBits, bool allowClearedFixedBit)
    {
        if (!QuicVersionNegotiation.IsSupportedTransportVersion(packetVersion))
        {
            return false;
        }

        if (!allowClearedFixedBit
            && (headerControlBits & QuicPacketHeaderBits.FixedBitMask) == 0)
        {
            return false;
        }

        byte longPacketTypeBits = (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift);
        return QuicVersionNegotiation.IsLongHeaderPacketType(packetVersion, longPacketTypeBits, QuicLongPacketType.Initial);
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
        QuicInitialPacketProtectionMaterial packetProtectionMaterial,
        Span<byte> packet,
        int packetNumberOffset,
        int packetNumberLength)
    {
        Span<byte> mask = stackalloc byte[HeaderProtectionKeyLength];
        if (!packetProtectionMaterial.TryGenerateHeaderProtectionMask(
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

    private static ReadOnlySpan<byte> GetInitialSalt(uint version)
    {
        return version switch
        {
            QuicVersionNegotiation.Version1 => InitialSaltV1,
            QuicVersionNegotiation.Version2 => InitialSaltV2,
            _ => throw new NotSupportedException($"Version 0x{version:X8} does not define an Initial salt."),
        };
    }

    private static ReadOnlySpan<byte> GetInitialKeyLabel(uint version)
    {
        return version switch
        {
            QuicVersionNegotiation.Version1 => QuicKeyLabel,
            QuicVersionNegotiation.Version2 => QuicV2KeyLabel,
            _ => throw new NotSupportedException($"Version 0x{version:X8} does not define an Initial key label."),
        };
    }

    private static ReadOnlySpan<byte> GetInitialIvLabel(uint version)
    {
        return version switch
        {
            QuicVersionNegotiation.Version1 => QuicIvLabel,
            QuicVersionNegotiation.Version2 => QuicV2IvLabel,
            _ => throw new NotSupportedException($"Version 0x{version:X8} does not define an Initial IV label."),
        };
    }

    private static ReadOnlySpan<byte> GetInitialHeaderProtectionLabel(uint version)
    {
        return version switch
        {
            QuicVersionNegotiation.Version1 => QuicHpLabel,
            QuicVersionNegotiation.Version2 => QuicV2HpLabel,
            _ => throw new NotSupportedException($"Version 0x{version:X8} does not define an Initial header-protection label."),
        };
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
    private readonly QuicPacketProtectionCryptoContext cryptoContext;

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
        cryptoContext = new QuicPacketProtectionCryptoContext(algorithm, aeadKey, headerProtectionKey);
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

    internal byte[] AeadIvBytes => aeadIv;

    internal bool TryEncryptPacketPayload(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> plaintext,
        Span<byte> ciphertext,
        Span<byte> tag,
        ReadOnlySpan<byte> associatedData)
    {
        return cryptoContext is not null
            && cryptoContext.TryEncryptPacketPayload(nonce, plaintext, ciphertext, tag, associatedData);
    }

    internal bool TryDecryptPacketPayload(
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        return cryptoContext is not null
            && cryptoContext.TryDecryptPacketPayload(nonce, ciphertext, tag, plaintext, associatedData);
    }

    internal bool TryGenerateHeaderProtectionMask(
        ReadOnlySpan<byte> sample,
        Span<byte> destination)
    {
        return cryptoContext is not null
            && cryptoContext.TryGenerateHeaderProtectionMask(sample, destination);
    }
}
