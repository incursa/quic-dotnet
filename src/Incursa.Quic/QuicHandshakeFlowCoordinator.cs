using System.Buffers.Binary;

namespace Incursa.Quic;

/// <summary>
/// Owns the narrow Handshake packet assembly and open/parse glue used by the connection runtime.
/// </summary>
internal sealed class QuicHandshakeFlowCoordinator
{
    private const int HandshakePacketNumberLength = 4;
    private const int HandshakeMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int LongHeaderFormLength = 1;
    private const int LongHeaderVersionLength = sizeof(uint);
    private const int LongHeaderFixedPrefixLength = LongHeaderFormLength + LongHeaderVersionLength;
    private const int DestinationConnectionIdLengthOffset = LongHeaderFixedPrefixLength;
    private const int DestinationConnectionIdOffset = DestinationConnectionIdLengthOffset + 1;
    private const int CryptoFramePayloadBufferOverhead = 32;

    private readonly byte[] destinationConnectionId;
    private readonly byte[] sourceConnectionId;
    private ulong nextPacketNumber;

    public QuicHandshakeFlowCoordinator(
        ReadOnlyMemory<byte> destinationConnectionId = default,
        ReadOnlyMemory<byte> sourceConnectionId = default)
    {
        this.destinationConnectionId = destinationConnectionId.ToArray();
        this.sourceConnectionId = sourceConnectionId.ToArray();
    }

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
        protectedPacket = [];

        if (cryptoPayload.IsEmpty
            || !QuicHandshakePacketProtection.TryCreate(material, out QuicHandshakePacketProtection protection))
        {
            return false;
        }

        if (!TryBuildHandshakePlaintextPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            out byte[] plaintextPacket))
        {
            return false;
        }

        byte[] protectedPacketBuffer = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        if (!protection.TryProtect(plaintextPacket, protectedPacketBuffer, out int protectedBytesWritten))
        {
            return false;
        }

        if (protectedBytesWritten != protectedPacketBuffer.Length)
        {
            return false;
        }

        protectedPacket = protectedPacketBuffer;
        return true;
    }

    private bool TryBuildHandshakePlaintextPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        out byte[] plaintextPacket)
    {
        plaintextPacket = [];

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

        byte headerControlBits = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (QuicLongPacketTypeBits.Handshake << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | (packetNumberLength - 1));

        plaintextPacket = BuildLongHeaderPacket(
            headerControlBits,
            QuicVersionNegotiation.Version1,
            destinationConnectionId,
            sourceConnectionId,
            versionSpecificData);

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
        ReadOnlySpan<byte> versionSpecificData)
    {
        byte[] packet = new byte[1 + sizeof(uint) + 1 + destinationConnectionId.Length + 1 + sourceConnectionId.Length + versionSpecificData.Length];
        packet[0] = (byte)(QuicPacketHeaderBits.HeaderFormBitMask | (headerControlBits & QuicPacketHeaderBits.HeaderControlBitsMask));
        BinaryPrimitives.WriteUInt32BigEndian(packet.AsSpan(1, sizeof(uint)), version);
        packet[DestinationConnectionIdLengthOffset] = (byte)destinationConnectionId.Length;

        int sourceConnectionIdLengthOffset = DestinationConnectionIdOffset + destinationConnectionId.Length;
        destinationConnectionId.CopyTo(packet.AsSpan(DestinationConnectionIdOffset));
        packet[sourceConnectionIdLengthOffset] = (byte)sourceConnectionId.Length;

        int versionSpecificDataOffset = sourceConnectionIdLengthOffset + 1 + sourceConnectionId.Length;
        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }
}
