using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Incursa.Quic;

/// <summary>
/// Owns the narrow Handshake packet assembly and open/parse glue used by the connection runtime.
/// </summary>
internal sealed class QuicHandshakeFlowCoordinator
{
    private const int HandshakePacketNumberLength = 4;
    private const int HandshakeMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int ApplicationPacketNumberLength = 4;
    private const int ApplicationMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int LongHeaderConnectionIdLengthFieldsLength = 1 + 1;
    private const int HeaderProtectionMaskLength = QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int LongHeaderFormLength = 1;
    private const int LongHeaderVersionLength = sizeof(uint);
    private const int LongHeaderFixedPrefixLength = LongHeaderFormLength + LongHeaderVersionLength;
    private const int DestinationConnectionIdLengthOffset = LongHeaderFixedPrefixLength;
    private const int DestinationConnectionIdOffset = DestinationConnectionIdLengthOffset + 1;
    private const int CryptoFramePayloadBufferOverhead = 32;

    private byte[] initialDestinationConnectionId;
    private byte[] destinationConnectionId;
    private byte[] sourceConnectionId;
    private ulong nextPacketNumber;
    private ulong nextApplicationPacketNumber;

    public QuicHandshakeFlowCoordinator(
        ReadOnlyMemory<byte> initialDestinationConnectionId = default,
        ReadOnlyMemory<byte> sourceConnectionId = default)
    {
        this.initialDestinationConnectionId = initialDestinationConnectionId.ToArray();
        this.destinationConnectionId = initialDestinationConnectionId.ToArray();
        this.sourceConnectionId = sourceConnectionId.ToArray();
    }

    internal bool TrySetDestinationConnectionId(ReadOnlySpan<byte> connectionId)
    {
        return TrySetInitialDestinationConnectionId(connectionId);
    }

    internal bool TrySetInitialDestinationConnectionId(ReadOnlySpan<byte> connectionId)
    {
        return TrySetConnectionId(ref initialDestinationConnectionId, connectionId, allowOverwrite: false);
    }

    internal bool TrySetHandshakeDestinationConnectionId(ReadOnlySpan<byte> connectionId)
    {
        return TrySetConnectionId(ref destinationConnectionId, connectionId, allowOverwrite: true);
    }

    internal bool TrySetSourceConnectionId(ReadOnlySpan<byte> connectionId)
    {
        return TrySetConnectionId(ref sourceConnectionId, connectionId, allowOverwrite: false);
    }

    internal ReadOnlyMemory<byte> InitialDestinationConnectionId => initialDestinationConnectionId;

    internal ReadOnlyMemory<byte> DestinationConnectionId => destinationConnectionId;

    internal ReadOnlyMemory<byte> SourceConnectionId => sourceConnectionId;

    /// <summary>
    /// Opens a protected Handshake packet and returns the unprotected packet bytes plus payload layout.
    /// </summary>
    public bool TryOpenHandshakePacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        openedPacket = [];
        payloadOffset = default;
        payloadLength = default;

        if (!QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection protection))
        {
            return false;
        }

        byte[] openedPacketBuffer = new byte[protectedPacket.Length];
        if (!protection.TryOpen(protectedPacket, openedPacketBuffer, out int openedBytesWritten))
        {
            return false;
        }

        openedPacket = openedPacketBuffer.AsSpan(0, openedBytesWritten).ToArray();
        if (!TryParseHandshakePayloadLayout(
            openedPacket,
            out payloadOffset,
            out payloadLength))
        {
            return false;
        }

        return true;
    }

    /// <summary>
    /// Formats and protects a Handshake packet from a CRYPTO payload and its stream offset.
    /// </summary>
    public bool TryBuildProtectedHandshakePacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        QuicTlsPacketProtectionMaterial material,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset,
            material,
            out _,
            out protectedPacket);
    }

    /// <summary>
    /// Formats and protects a Handshake packet from a CRYPTO payload and its stream offset.
    /// </summary>
    public bool TryBuildProtectedHandshakePacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        QuicTlsPacketProtectionMaterial material,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        protectedPacket = [];
        packetNumber = default;

        if (cryptoPayload.IsEmpty
            || !QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection protection))
        {
            return false;
        }

        if (!TryBuildHandshakePlaintextPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            out packetNumber,
            out byte[] plaintextPacket))
        {
            packetNumber = default;
            return false;
        }

        byte[] protectedPacketBuffer = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        if (!protection.TryProtect(plaintextPacket, protectedPacketBuffer, out int protectedBytesWritten))
        {
            packetNumber = default;
            return false;
        }

        if (protectedBytesWritten != protectedPacketBuffer.Length)
        {
            packetNumber = default;
            return false;
        }

        protectedPacket = protectedPacketBuffer;
        return true;
    }

    /// <summary>
    /// Formats and protects a 1-RTT short-header packet from a STREAM/control payload.
    /// </summary>
    public bool TryBuildProtectedApplicationDataPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            out _,
            out protectedPacket);
    }

    /// <summary>
    /// Formats and protects a 1-RTT short-header packet from a STREAM/control payload.
    /// </summary>
    public bool TryBuildProtectedApplicationDataPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            keyPhase: false,
            out packetNumber,
            out protectedPacket);
    }

    /// <summary>
    /// Formats and protects a 1-RTT short-header packet from a STREAM/control payload and an explicit Key Phase bit.
    /// </summary>
    public bool TryBuildProtectedApplicationDataPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            keyPhase,
            out _,
            out protectedPacket);
    }

    /// <summary>
    /// Formats and protects a 1-RTT short-header packet from a STREAM/control payload and an explicit Key Phase bit.
    /// </summary>
    public bool TryBuildProtectedApplicationDataPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        protectedPacket = [];
        packetNumber = default;

        if (applicationPayload.IsEmpty
            || destinationConnectionId.Length == 0
            || material.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        ulong currentPacketNumber = nextApplicationPacketNumber;
        if (!TryBuildApplicationDataPlaintextPacket(
            applicationPayload,
            keyPhase,
            out byte[] plaintextPacket,
            out int packetNumberOffset,
            out int packetNumberLength))
        {
            return false;
        }

        if (!TryProtectApplicationDataPacket(
            material,
            plaintextPacket,
            packetNumberOffset,
            packetNumberLength,
            out protectedPacket))
        {
            return false;
        }

        packetNumber = currentPacketNumber;
        nextApplicationPacketNumber = nextApplicationPacketNumber == ulong.MaxValue ? 0 : nextApplicationPacketNumber + 1;
        return true;
    }

    /// <summary>
    /// Formats and protects a 0-RTT long-header packet from an application payload.
    /// </summary>
    internal bool TryBuildProtectedZeroRttApplicationPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedZeroRttApplicationPacket(
            applicationPayload,
            material,
            out _,
            out protectedPacket);
    }

    /// <summary>
    /// Formats and protects a 0-RTT long-header packet from an application payload.
    /// </summary>
    internal bool TryBuildProtectedZeroRttApplicationPacket(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        protectedPacket = [];
        packetNumber = default;

        if (applicationPayload.IsEmpty
            || material.EncryptionLevel != QuicTlsEncryptionLevel.ZeroRtt)
        {
            return false;
        }

        ulong currentPacketNumber = nextApplicationPacketNumber;
        if (!TryBuildZeroRttApplicationPlaintextPacket(
            applicationPayload,
            out byte[] plaintextPacket,
            out int packetNumberOffset,
            out int packetNumberLength))
        {
            return false;
        }

        if (!TryProtectApplicationDataPacket(
            material,
            plaintextPacket,
            packetNumberOffset,
            packetNumberLength,
            out protectedPacket))
        {
            return false;
        }

        packetNumber = currentPacketNumber;
        nextApplicationPacketNumber = nextApplicationPacketNumber == ulong.MaxValue ? 0 : nextApplicationPacketNumber + 1;
        return true;
    }

    /// <summary>
    /// Opens a protected 1-RTT short-header packet and returns the unprotected packet bytes plus payload layout.
    /// </summary>
    public bool TryOpenProtectedApplicationDataPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        return TryOpenProtectedApplicationDataPacket(
            protectedPacket,
            material,
            out openedPacket,
            out payloadOffset,
            out payloadLength,
            out _);
    }

    /// <summary>
    /// Opens a protected 1-RTT short-header packet, returns the unprotected packet bytes plus payload layout, and reports the observed Key Phase bit.
    /// </summary>
    public bool TryOpenProtectedApplicationDataPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out bool keyPhase)
    {
        openedPacket = [];
        payloadOffset = default;
        payloadLength = default;
        keyPhase = default;

        if (destinationConnectionId.Length == 0
            || material.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        for (int packetNumberLength = 1; packetNumberLength <= ApplicationPacketNumberLength; packetNumberLength++)
        {
            if (TryOpenApplicationDataPacket(
                protectedPacket,
                material,
                packetNumberLength,
                out openedPacket,
                out payloadOffset,
                out payloadLength,
                out keyPhase))
            {
                return true;
            }
        }

        return false;
    }

    internal bool TryBuildHandshakePlaintextPacketForTest(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        out byte[] plaintextPacket)
    {
        return TryBuildHandshakePlaintextPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            out _,
            out plaintextPacket);
    }

    /// <summary>
    /// Opens a protected Initial packet and returns the unprotected packet bytes plus payload layout.
    /// </summary>
    public bool TryOpenInitialPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicInitialPacketProtection protection,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        openedPacket = [];
        payloadOffset = default;
        payloadLength = default;

        byte[] openedPacketBuffer = new byte[protectedPacket.Length];
        if (!protection.TryOpen(protectedPacket, openedPacketBuffer, out int openedBytesWritten))
        {
            return false;
        }

        openedPacket = openedPacketBuffer.AsSpan(0, openedBytesWritten).ToArray();
        return TryParseInitialPayloadLayout(
            openedPacket,
            out payloadOffset,
            out payloadLength);
    }

    /// <summary>
    /// Formats and protects an Initial packet from a CRYPTO payload and its stream offset.
    /// </summary>
    public bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        QuicInitialPacketProtection protection,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            initialDestinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            protection,
            out _,
            out protectedPacket);
    }

    public bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            initialDestinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            protection,
            out packetNumber,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacketForHandshakeDestination(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        QuicInitialPacketProtection protection,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketForHandshakeDestination(
            cryptoPayload,
            cryptoPayloadOffset,
            protection,
            out _,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacketForHandshakeDestination(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            protection,
            out packetNumber,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        QuicInitialPacketProtection protection,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketCore(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            token,
            protection,
            out _,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketCore(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            token,
            protection,
            out packetNumber,
            out protectedPacket);
    }

    private bool TryBuildProtectedInitialPacketCore(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        protectedPacket = [];
        packetNumber = default;

        if (cryptoPayload.IsEmpty
            || !TryBuildInitialPlaintextPacket(
                cryptoPayload,
                cryptoPayloadOffset,
                destinationConnectionId,
                token,
                out packetNumber,
                out byte[] plaintextPacket))
        {
            return false;
        }

        byte[] protectedPacketBuffer = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        if (!protection.TryProtect(plaintextPacket, protectedPacketBuffer, out int protectedBytesWritten))
        {
            packetNumber = default;
            return false;
        }

        if (protectedBytesWritten != protectedPacketBuffer.Length)
        {
            packetNumber = default;
            return false;
        }

        protectedPacket = protectedPacketBuffer;
        return true;
    }

    private bool TryBuildHandshakePlaintextPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        out ulong packetNumber,
        out byte[] plaintextPacket)
    {
        plaintextPacket = [];
        packetNumber = default;

        if (!TryFormatCryptoFramePayload(
            cryptoPayload,
            cryptoPayloadOffset,
            out byte[] cryptoFramePayload,
            out int cryptoFramePayloadLength))
        {
            return false;
        }

        int paddedPayloadLength = Math.Max(cryptoFramePayloadLength, HandshakeMinimumProtectedPayloadLength);
        int packetNumberLength = HandshakePacketNumberLength;

        Span<byte> lengthFieldBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        ulong lengthFieldValue = (ulong)(packetNumberLength + paddedPayloadLength + QuicInitialPacketProtection.AuthenticationTagLength);
        if (!QuicVariableLengthInteger.TryFormat(lengthFieldValue, lengthFieldBuffer, out int lengthFieldBytesWritten))
        {
            return false;
        }

        byte[] versionSpecificData = new byte[lengthFieldBytesWritten + packetNumberLength + paddedPayloadLength];
        int versionSpecificDataIndex = 0;

        lengthFieldBuffer[..lengthFieldBytesWritten].CopyTo(versionSpecificData);
        versionSpecificDataIndex += lengthFieldBytesWritten;

        BinaryPrimitives.WriteUInt32BigEndian(
            versionSpecificData.AsSpan(versionSpecificDataIndex, packetNumberLength),
            unchecked((uint)nextPacketNumber));
        versionSpecificDataIndex += packetNumberLength;

        cryptoFramePayload.AsSpan(0, cryptoFramePayloadLength).CopyTo(versionSpecificData.AsSpan(versionSpecificDataIndex));
        versionSpecificDataIndex += cryptoFramePayloadLength;

        if (paddedPayloadLength > cryptoFramePayloadLength)
        {
            versionSpecificData.AsSpan(versionSpecificDataIndex, paddedPayloadLength - cryptoFramePayloadLength).Fill(0);
        }

        packetNumber = nextPacketNumber;
        byte headerControlBits = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (QuicLongPacketTypeBits.Handshake << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | (packetNumberLength - 1));

        plaintextPacket = BuildLongHeaderPacket(
            headerControlBits,
            QuicVersionNegotiation.Version1,
            destinationConnectionId,
            sourceConnectionId,
            token: ReadOnlySpan<byte>.Empty,
            versionSpecificData,
            includeTokenLengthField: false);

        nextPacketNumber = nextPacketNumber == ulong.MaxValue ? 0 : nextPacketNumber + 1;
        return true;
    }

    private bool TryBuildInitialPlaintextPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        out ulong packetNumber,
        out byte[] plaintextPacket)
    {
        plaintextPacket = [];
        packetNumber = default;

        if (destinationConnectionId.Length == 0 || sourceConnectionId.Length == 0)
        {
            return false;
        }

        if (!TryFormatCryptoFramePayload(
            cryptoPayload,
            cryptoPayloadOffset,
            out byte[] cryptoFramePayload,
            out int cryptoFramePayloadLength))
        {
            return false;
        }

        int paddedPayloadLength = Math.Max(cryptoFramePayloadLength, HandshakeMinimumProtectedPayloadLength);
        int packetNumberLength = HandshakePacketNumberLength;
        int lengthFieldBytesWritten;
        Span<byte> lengthFieldBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];

        while (true)
        {
            ulong lengthFieldValue = (ulong)(packetNumberLength + paddedPayloadLength + QuicInitialPacketProtection.AuthenticationTagLength);
            if (!QuicVariableLengthInteger.TryFormat(lengthFieldValue, lengthFieldBuffer, out lengthFieldBytesWritten))
            {
                return false;
            }

            int minimumProtectedPacketLength = 1
                + LongHeaderVersionLength
                + 1 + destinationConnectionId.Length
                + 1 + sourceConnectionId.Length
                + 1
                + lengthFieldBytesWritten
                + packetNumberLength
                + paddedPayloadLength
                + QuicInitialPacketProtection.AuthenticationTagLength;
            if (minimumProtectedPacketLength >= QuicVersionNegotiation.Version1MinimumDatagramPayloadSize)
            {
                break;
            }

            paddedPayloadLength += QuicVersionNegotiation.Version1MinimumDatagramPayloadSize - minimumProtectedPacketLength;
        }

        byte[] versionSpecificData = new byte[lengthFieldBytesWritten + packetNumberLength + paddedPayloadLength];
        int versionSpecificDataIndex = 0;

        lengthFieldBuffer[..lengthFieldBytesWritten].CopyTo(versionSpecificData);
        versionSpecificDataIndex += lengthFieldBytesWritten;

        BinaryPrimitives.WriteUInt32BigEndian(
            versionSpecificData.AsSpan(versionSpecificDataIndex, packetNumberLength),
            unchecked((uint)nextPacketNumber));
        versionSpecificDataIndex += packetNumberLength;

        cryptoFramePayload.AsSpan(0, cryptoFramePayloadLength).CopyTo(versionSpecificData.AsSpan(versionSpecificDataIndex));
        versionSpecificDataIndex += cryptoFramePayloadLength;

        if (paddedPayloadLength > cryptoFramePayloadLength)
        {
            versionSpecificData.AsSpan(versionSpecificDataIndex, paddedPayloadLength - cryptoFramePayloadLength).Fill(0);
        }

        packetNumber = nextPacketNumber;
        byte headerControlBits = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (QuicLongPacketTypeBits.Initial << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | (packetNumberLength - 1));

        plaintextPacket = BuildLongHeaderPacket(
            headerControlBits,
            QuicVersionNegotiation.Version1,
            destinationConnectionId,
            sourceConnectionId,
            token,
            versionSpecificData,
            includeTokenLengthField: true);

        nextPacketNumber = nextPacketNumber == ulong.MaxValue ? 0 : nextPacketNumber + 1;
        return true;
    }

    private static bool TryFormatCryptoFramePayload(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        out byte[] cryptoFramePayload,
        out int cryptoFramePayloadLength)
    {
        cryptoFramePayload = [];
        cryptoFramePayloadLength = default;

        if (cryptoPayloadOffset > QuicVariableLengthInteger.MaxValue - (ulong)cryptoPayload.Length)
        {
            return false;
        }

        if (cryptoPayload.Length > int.MaxValue - CryptoFramePayloadBufferOverhead)
        {
            return false;
        }

        byte[] buffer = new byte[cryptoPayload.Length + CryptoFramePayloadBufferOverhead];
        if (!QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(cryptoPayloadOffset, cryptoPayload),
            buffer,
            out int bytesWritten))
        {
            return false;
        }

        cryptoFramePayload = buffer;
        cryptoFramePayloadLength = bytesWritten;
        return true;
    }

    private static bool TryParseHandshakePayloadLayout(
        ReadOnlySpan<byte> openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        payloadOffset = default;
        payloadLength = default;

        if (!QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData)
            || version != QuicVersionNegotiation.Version1
            || ((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift) != QuicLongPacketTypeBits.Handshake
            || !QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong lengthFieldValue, out int lengthBytes))
        {
            return false;
        }

        int packetNumberLength = (headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        int remainingAfterLength = versionSpecificData.Length - lengthBytes;
        ulong availableBytesIncludingTag = (ulong)remainingAfterLength + QuicInitialPacketProtection.AuthenticationTagLength;
        if (lengthFieldValue < (ulong)(packetNumberLength + QuicInitialPacketProtection.AuthenticationTagLength)
            || lengthFieldValue > availableBytesIncludingTag)
        {
            return false;
        }

        int versionSpecificDataOffset = openedPacket.Length - versionSpecificData.Length;
        payloadOffset = versionSpecificDataOffset + lengthBytes + packetNumberLength;
        payloadLength = checked((int)lengthFieldValue) - packetNumberLength - QuicInitialPacketProtection.AuthenticationTagLength;
        return payloadOffset >= 0 && payloadLength >= 0 && payloadOffset + payloadLength <= openedPacket.Length;
    }

    private static byte[] BuildLongHeaderPacket(
        byte headerControlBits,
        uint version,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> versionSpecificData,
        bool includeTokenLengthField)
    {
        byte[] tokenLengthBuffer = [];
        int tokenLengthBytesWritten = 0;
        if (includeTokenLengthField)
        {
            tokenLengthBuffer = new byte[QuicVariableLengthInteger.MaxEncodedLength];
            if (!QuicVariableLengthInteger.TryFormat((ulong)token.Length, tokenLengthBuffer, out tokenLengthBytesWritten))
            {
                throw new InvalidOperationException("The token length could not be formatted.");
            }
        }

        byte[] packet = new byte[1
            + sizeof(uint)
            + 1 + destinationConnectionId.Length
            + 1 + sourceConnectionId.Length
            + (includeTokenLengthField ? tokenLengthBytesWritten + token.Length : 0)
            + versionSpecificData.Length];
        packet[0] = (byte)(QuicPacketHeaderBits.HeaderFormBitMask | (headerControlBits & QuicPacketHeaderBits.HeaderControlBitsMask));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
        packet[DestinationConnectionIdLengthOffset] = (byte)destinationConnectionId.Length;

        int sourceConnectionIdLengthOffset = DestinationConnectionIdOffset + destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(DestinationConnectionIdOffset));
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length;
        if (includeTokenLengthField)
        {
            tokenLengthBuffer.AsSpan(0, tokenLengthBytesWritten).CopyTo(packet.AsSpan(versionSpecificDataOffset));
            token.CopyTo(packet.AsSpan(versionSpecificDataOffset + tokenLengthBytesWritten));
            versionSpecificDataOffset += tokenLengthBytesWritten + token.Length;
        }

        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }

    private static bool TryParseInitialPayloadLayout(
        ReadOnlySpan<byte> openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        payloadOffset = default;
        payloadLength = default;

        if (!QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData)
            || version != QuicVersionNegotiation.Version1
            || ((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift) != QuicLongPacketTypeBits.Initial
            || !QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes))
        {
            return false;
        }

        int remainingAfterToken = versionSpecificData.Length - tokenLengthBytes;
        if (tokenLength > (ulong)remainingAfterToken)
        {
            return false;
        }

        ReadOnlySpan<byte> afterToken = versionSpecificData.Slice(tokenLengthBytes + (int)tokenLength);
        if (!QuicVariableLengthInteger.TryParse(afterToken, out ulong lengthFieldValue, out int lengthFieldBytes))
        {
            return false;
        }

        int packetNumberLength = (headerControlBits & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1;
        int remainingAfterLength = afterToken.Length - lengthFieldBytes;
        ulong availableBytesIncludingTag = (ulong)remainingAfterLength + QuicInitialPacketProtection.AuthenticationTagLength;
        if (lengthFieldValue < (ulong)(packetNumberLength + QuicInitialPacketProtection.AuthenticationTagLength)
            || lengthFieldValue > availableBytesIncludingTag)
        {
            return false;
        }

        int versionSpecificDataOffset = openedPacket.Length - versionSpecificData.Length;
        payloadOffset = versionSpecificDataOffset + tokenLengthBytes + (int)tokenLength + lengthFieldBytes + packetNumberLength;
        payloadLength = checked((int)lengthFieldValue) - packetNumberLength - QuicInitialPacketProtection.AuthenticationTagLength;
        return payloadOffset >= 0 && payloadLength >= 0 && payloadOffset + payloadLength <= openedPacket.Length;
    }

    private bool TryBuildApplicationDataPlaintextPacket(
        ReadOnlySpan<byte> applicationPayload,
        bool keyPhase,
        out byte[] plaintextPacket,
        out int packetNumberOffset,
        out int packetNumberLength)
    {
        plaintextPacket = [];
        packetNumberOffset = default;
        packetNumberLength = ApplicationPacketNumberLength;

        if (destinationConnectionId.Length == 0
            || applicationPayload.Length > int.MaxValue - 1 - destinationConnectionId.Length - packetNumberLength - ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        int paddedPayloadLength = Math.Max(applicationPayload.Length, ApplicationMinimumProtectedPayloadLength);
        packetNumberOffset = 1 + destinationConnectionId.Length;

        byte[] packet = new byte[packetNumberOffset + packetNumberLength + paddedPayloadLength];
        packet[0] = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (keyPhase ? QuicPacketHeaderBits.KeyPhaseBitMask : 0)
            | (packetNumberLength - 1));
        destinationConnectionId.CopyTo(packet.AsSpan(1));

        BinaryPrimitives.WriteUInt32BigEndian(
            packet.AsSpan(packetNumberOffset, packetNumberLength),
            unchecked((uint)nextApplicationPacketNumber));

        applicationPayload.CopyTo(packet.AsSpan(packetNumberOffset + packetNumberLength));

        if (paddedPayloadLength > applicationPayload.Length)
        {
            packet.AsSpan(packetNumberOffset + packetNumberLength + applicationPayload.Length, paddedPayloadLength - applicationPayload.Length).Fill(0);
        }

        plaintextPacket = packet;
        return true;
    }

    private bool TryBuildZeroRttApplicationPlaintextPacket(
        ReadOnlySpan<byte> applicationPayload,
        out byte[] plaintextPacket,
        out int packetNumberOffset,
        out int packetNumberLength)
    {
        plaintextPacket = [];
        packetNumberOffset = default;
        packetNumberLength = ApplicationPacketNumberLength;

        if (initialDestinationConnectionId.Length == 0
            || sourceConnectionId.Length == 0
            || applicationPayload.Length > int.MaxValue - LongHeaderFixedPrefixLength - LongHeaderConnectionIdLengthFieldsLength - initialDestinationConnectionId.Length - sourceConnectionId.Length - packetNumberLength - ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        int paddedPayloadLength = Math.Max(applicationPayload.Length, ApplicationMinimumProtectedPayloadLength);
        Span<byte> lengthFieldBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        ulong lengthFieldValue = (ulong)(packetNumberLength + paddedPayloadLength + QuicInitialPacketProtection.AuthenticationTagLength);
        if (!QuicVariableLengthInteger.TryFormat(lengthFieldValue, lengthFieldBuffer, out int lengthFieldBytes))
        {
            return false;
        }

        int longHeaderPrefixLength = LongHeaderFixedPrefixLength
            + 1
            + initialDestinationConnectionId.Length
            + 1
            + sourceConnectionId.Length;
        if (longHeaderPrefixLength > int.MaxValue - lengthFieldBytes - packetNumberLength - paddedPayloadLength)
        {
            return false;
        }

        packetNumberOffset = longHeaderPrefixLength + lengthFieldBytes;

        byte[] versionSpecificData = new byte[lengthFieldBytes + packetNumberLength + paddedPayloadLength];
        lengthFieldBuffer.Slice(0, lengthFieldBytes).CopyTo(versionSpecificData);
        BinaryPrimitives.WriteUInt32BigEndian(
            versionSpecificData.AsSpan(lengthFieldBytes, packetNumberLength),
            unchecked((uint)nextApplicationPacketNumber));

        applicationPayload.CopyTo(versionSpecificData.AsSpan(lengthFieldBytes + packetNumberLength));
        if (paddedPayloadLength > applicationPayload.Length)
        {
            versionSpecificData.AsSpan(
                lengthFieldBytes + packetNumberLength + applicationPayload.Length,
                paddedPayloadLength - applicationPayload.Length).Fill(0);
        }

        byte headerControlBits = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (QuicLongPacketTypeBits.ZeroRtt << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | (packetNumberLength - 1));

        plaintextPacket = BuildLongHeaderPacket(
            headerControlBits,
            QuicVersionNegotiation.Version1,
            initialDestinationConnectionId,
            sourceConnectionId,
            token: ReadOnlySpan<byte>.Empty,
            versionSpecificData,
            includeTokenLengthField: false);
        return true;
    }

    private bool TryProtectApplicationDataPacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> plaintextPacket,
        int packetNumberOffset,
        int packetNumberLength,
        out byte[] protectedPacket)
    {
        protectedPacket = [];

        if (!TryValidatePacketProtectionMaterial(material))
        {
            return false;
        }

        int plaintextPayloadLength = plaintextPacket.Length - packetNumberOffset - packetNumberLength;
        if (plaintextPayloadLength < ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        byte[] protectedPacketBuffer = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        plaintextPacket[..(packetNumberOffset + packetNumberLength)].CopyTo(protectedPacketBuffer);

        Span<byte> nonce = stackalloc byte[QuicInitialPacketProtection.AeadNonceLength];
        BuildNonce(
            material.AeadIvBytes,
            plaintextPacket,
            packetNumberOffset,
            packetNumberLength,
            nonce);

        if (!TryEncryptPacketPayload(
            material,
            nonce,
            plaintextPacket.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
            protectedPacketBuffer.AsSpan(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
            protectedPacketBuffer.AsSpan(plaintextPacket.Length, QuicInitialPacketProtection.AuthenticationTagLength),
            protectedPacketBuffer[..(packetNumberOffset + packetNumberLength)]))
        {
            return false;
        }

        if (!TryApplyHeaderProtection(
            material,
            protectedPacketBuffer,
            packetNumberOffset,
            packetNumberLength))
        {
            return false;
        }

        protectedPacket = protectedPacketBuffer;
        return true;
    }

    private bool TryOpenApplicationDataPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        int packetNumberLength,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out bool keyPhase)
    {
        openedPacket = [];
        payloadOffset = default;
        payloadLength = default;
        keyPhase = default;

        if (!TryValidatePacketProtectionMaterial(material)
            || packetNumberLength < 1
            || packetNumberLength > ApplicationPacketNumberLength
            || destinationConnectionId.Length == 0)
        {
            return false;
        }

        int packetNumberOffset = 1 + destinationConnectionId.Length;
        int ciphertextPayloadLength = protectedPacket.Length - packetNumberOffset - packetNumberLength - QuicInitialPacketProtection.AuthenticationTagLength;
        if (ciphertextPayloadLength < ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        int sampleOffset = packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset;
        if (protectedPacket.Length < sampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength)
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!TryGenerateHeaderProtectionMask(
            material.HeaderProtectionKeyBytes,
            protectedPacket.Slice(sampleOffset, QuicInitialPacketProtection.HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        byte unmaskedFirstByte = (byte)(protectedPacket[0] ^ (mask[0] & QuicPacketHeaderBits.TypeSpecificBitsMask));
        if ((unmaskedFirstByte & QuicPacketHeaderBits.HeaderFormBitMask) != 0
            || (unmaskedFirstByte & QuicPacketHeaderBits.FixedBitMask) == 0
            || ((unmaskedFirstByte & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1) != packetNumberLength
            || (unmaskedFirstByte & QuicPacketHeaderBits.ShortReservedBitsMask) != 0)
        {
            return false;
        }

        bool observedKeyPhase = (unmaskedFirstByte & QuicPacketHeaderBits.KeyPhaseBitMask) != 0;

        int unprotectedPacketLength = protectedPacket.Length - QuicInitialPacketProtection.AuthenticationTagLength;
        byte[] openedPacketBuffer = new byte[unprotectedPacketLength];
        protectedPacket[..packetNumberOffset].CopyTo(openedPacketBuffer);
        openedPacketBuffer[0] = unmaskedFirstByte;

        for (int i = 0; i < packetNumberLength; i++)
        {
            openedPacketBuffer[packetNumberOffset + i] = (byte)(protectedPacket[packetNumberOffset + i] ^ mask[1 + i]);
        }

        Span<byte> nonce = stackalloc byte[QuicInitialPacketProtection.AeadNonceLength];
        BuildNonce(
            material.AeadIvBytes,
            openedPacketBuffer,
            packetNumberOffset,
            packetNumberLength,
            nonce);

        if (!TryDecryptPacketPayload(
            material,
            nonce,
            protectedPacket.Slice(packetNumberOffset + packetNumberLength, ciphertextPayloadLength),
            protectedPacket.Slice(packetNumberOffset + packetNumberLength + ciphertextPayloadLength, QuicInitialPacketProtection.AuthenticationTagLength),
            openedPacketBuffer.AsSpan(packetNumberOffset + packetNumberLength, ciphertextPayloadLength),
            openedPacketBuffer[..(packetNumberOffset + packetNumberLength)]))
        {
            return false;
        }

        // Only publish the observed Key Phase after the packet authenticates successfully.
        keyPhase = observedKeyPhase;
        openedPacket = openedPacketBuffer;
        payloadOffset = packetNumberOffset + packetNumberLength;
        payloadLength = ciphertextPayloadLength;
        return true;
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

    private static bool TryDecryptPacketPayload(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        switch (material.Algorithm)
        {
            case QuicAeadAlgorithm.Aes128Gcm:
            case QuicAeadAlgorithm.Aes256Gcm:
                try
                {
                    using AesGcm aeadGcm = new(material.AeadKeyBytes, QuicInitialPacketProtection.AuthenticationTagLength);
                    aeadGcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                }
                catch (CryptographicException)
                {
                    return false;
                }

                return true;

            case QuicAeadAlgorithm.Aes128Ccm:
                try
                {
                    using AesCcm aeadCcm = new(material.AeadKeyBytes);
                    aeadCcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData);
                }
                catch (CryptographicException)
                {
                    return false;
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
        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!TryGenerateHeaderProtectionMask(
            material.HeaderProtectionKeyBytes,
            packet.Slice(packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset, QuicInitialPacketProtection.HeaderProtectionSampleLength),
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
        if (sample.Length < QuicInitialPacketProtection.HeaderProtectionSampleLength
            || destination.Length < HeaderProtectionMaskLength)
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
                destination[..HeaderProtectionMaskLength],
                PaddingMode.None) == HeaderProtectionMaskLength;
        }
        catch (CryptographicException)
        {
            return false;
        }
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
        for (int i = 0; i < packetNumberLength; i++)
        {
            nonce[nonceOffset + i] ^= packet[packetNumberOffset + i];
        }
    }

    private static bool TryValidatePacketProtectionMaterial(QuicTlsPacketProtectionMaterial material)
    {
        return QuicAeadAlgorithmMetadata.TryGetPacketProtectionLengths(
            material.Algorithm,
            out int expectedAeadKeyLength,
            out int expectedAeadIvLength,
            out int expectedHeaderProtectionKeyLength)
            && material.AeadKey.Length == expectedAeadKeyLength
            && material.AeadIv.Length == expectedAeadIvLength
            && material.HeaderProtectionKey.Length == expectedHeaderProtectionKeyLength;
    }

    private static bool TrySetConnectionId(ref byte[] target, ReadOnlySpan<byte> connectionId, bool allowOverwrite)
    {
        if (target.AsSpan().SequenceEqual(connectionId))
        {
            return true;
        }

        if (!allowOverwrite && target.Length != 0)
        {
            return false;
        }

        target = connectionId.ToArray();
        return true;
    }
}
