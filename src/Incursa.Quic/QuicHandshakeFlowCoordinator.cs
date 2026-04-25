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
    private const int ApplicationPacketNumberLength = 4;
    private const int MaximumConnectionIdLength = 20;
    private const int ApplicationMinimumProtectedPayloadLength =
        QuicInitialPacketProtection.HeaderProtectionSampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const int LongHeaderConnectionIdLengthFieldsLength = 1 + 1;
    private const int HeaderProtectionMaskLength = QuicInitialPacketProtection.HeaderProtectionSampleLength;
    private const byte SpinBitSelectionMask = 0x0F;
    private const int LongHeaderFormLength = 1;
    private const int LongHeaderVersionLength = sizeof(uint);
    private const int LongHeaderFixedPrefixLength = LongHeaderFormLength + LongHeaderVersionLength;
    private const int DestinationConnectionIdLengthOffset = LongHeaderFixedPrefixLength;
    private const int DestinationConnectionIdOffset = DestinationConnectionIdLengthOffset + 1;
    private const int CryptoFramePayloadBufferOverhead = 32;

    private byte[] initialDestinationConnectionId;
    private byte[] destinationConnectionId;
    private byte[] sourceConnectionId;
    private readonly bool enableRandomizedSpinBitSelection;
    private ulong nextPacketNumber;
    private ulong nextApplicationPacketNumber;

    public QuicHandshakeFlowCoordinator(
        ReadOnlyMemory<byte> initialDestinationConnectionId = default,
        ReadOnlyMemory<byte> sourceConnectionId = default,
        bool enableRandomizedSpinBitSelection = false)
    {
        this.initialDestinationConnectionId = initialDestinationConnectionId.ToArray();
        this.destinationConnectionId = initialDestinationConnectionId.ToArray();
        this.sourceConnectionId = sourceConnectionId.ToArray();
        this.enableRandomizedSpinBitSelection = enableRandomizedSpinBitSelection;
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

        byte[] openedPacketBuffer = QuicBufferPool.RentBytes(protectedPacket.Length);
        try
        {
            if (!protection.TryOpen(protectedPacket, openedPacketBuffer, out int openedBytesWritten))
            {
                return false;
            }

            if (!TryParseHandshakePayloadLayout(
                openedPacketBuffer.AsSpan(0, openedBytesWritten),
                out payloadOffset,
                out payloadLength))
            {
                return false;
            }

            openedPacket = openedPacketBuffer.AsSpan(0, openedBytesWritten).ToArray();
            return true;
        }
        finally
        {
            QuicBufferPool.ReturnBytes(openedPacketBuffer);
        }
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
    /// Formats and protects a Handshake packet from prefix frame bytes plus a CRYPTO payload and its stream offset.
    /// </summary>
    public bool TryBuildProtectedHandshakePacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicTlsPacketProtectionMaterial material,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset,
            prefixFramePayload,
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
        return TryBuildProtectedHandshakePacket(
            cryptoPayload,
            cryptoPayloadOffset,
            ReadOnlySpan<byte>.Empty,
            material,
            out packetNumber,
            out protectedPacket);
    }

    /// <summary>
    /// Formats and protects a Handshake packet from prefix frame bytes plus a CRYPTO payload and its stream offset.
    /// </summary>
    public bool TryBuildProtectedHandshakePacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> prefixFramePayload,
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
            prefixFramePayload,
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

    internal bool TryBuildProtectedHandshakePacketForRetransmission(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        QuicTlsPacketProtectionMaterial material,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedHandshakePacketForRetransmission(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            sourceConnectionId,
            ReadOnlySpan<byte>.Empty,
            material,
            out packetNumber,
            out protectedPacket);
    }

    internal bool TryBuildProtectedHandshakePacketForRetransmission(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicTlsPacketProtectionMaterial material,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        byte[] savedDestinationConnectionId = this.destinationConnectionId;
        byte[] savedSourceConnectionId = this.sourceConnectionId;

        try
        {
            this.destinationConnectionId = destinationConnectionId.ToArray();
            this.sourceConnectionId = sourceConnectionId.ToArray();
            return TryBuildProtectedHandshakePacket(
                cryptoPayload,
                cryptoPayloadOffset,
                prefixFramePayload,
                material,
                out packetNumber,
                out protectedPacket);
        }
        finally
        {
            this.destinationConnectionId = savedDestinationConnectionId;
            this.sourceConnectionId = savedSourceConnectionId;
        }
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
            || destinationConnectionId.Length > MaximumConnectionIdLength
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

    internal bool TryBuildProtectedApplicationDataPacketLease(
        ReadOnlySpan<byte> applicationPayload,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        out ulong packetNumber,
        out QuicBufferLease protectedPacket)
    {
        protectedPacket = default;
        packetNumber = default;

        if (applicationPayload.IsEmpty
            || destinationConnectionId.Length > MaximumConnectionIdLength
            || material.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        ulong currentPacketNumber = nextApplicationPacketNumber;
        if (!TryBuildApplicationDataPlaintextPacket(
                applicationPayload,
                keyPhase,
                out QuicBufferLease plaintextPacket,
                out int packetNumberOffset,
                out int packetNumberLength))
        {
            return false;
        }

        try
        {
            if (!TryProtectApplicationDataPacket(
                    material,
                    plaintextPacket.Span,
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
        finally
        {
            plaintextPacket.Dispose();
        }
    }

    internal bool TryBuildProtectedApplicationDataPacketForRetransmission(
        ReadOnlySpan<byte> applicationPayload,
        ulong minimumPacketNumberExclusive,
        QuicTlsPacketProtectionMaterial material,
        bool keyPhase,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        protectedPacket = [];
        packetNumber = default;

        if (minimumPacketNumberExclusive == ulong.MaxValue)
        {
            return false;
        }

        if (nextApplicationPacketNumber <= minimumPacketNumberExclusive)
        {
            nextApplicationPacketNumber = minimumPacketNumberExclusive + 1;
        }

        return TryBuildProtectedApplicationDataPacket(
            applicationPayload,
            material,
            keyPhase,
            out packetNumber,
            out protectedPacket);
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

        if (destinationConnectionId.Length > MaximumConnectionIdLength
            || material.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        int sourceConnectionIdLength = sourceConnectionId.Length;
        int destinationConnectionIdLength = destinationConnectionId.Length;
        if (sourceConnectionIdLength > 0)
        {
            for (int packetNumberLength = 1; packetNumberLength <= ApplicationPacketNumberLength; packetNumberLength++)
            {
                if (TryOpenApplicationDataPacket(
                    protectedPacket,
                    material,
                    sourceConnectionIdLength,
                    packetNumberLength,
                    out openedPacket,
                    out payloadOffset,
                    out payloadLength,
                    out keyPhase))
                {
                    return true;
                }
            }

            if (sourceConnectionIdLength == destinationConnectionIdLength)
            {
                return false;
            }
        }

        for (int packetNumberLength = 1; packetNumberLength <= ApplicationPacketNumberLength; packetNumberLength++)
        {
            if (TryOpenApplicationDataPacket(
                protectedPacket,
                material,
                destinationConnectionIdLength,
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

    internal bool TryOpenProtectedApplicationDataPacketLease(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        out QuicBufferLease openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out bool keyPhase)
    {
        openedPacket = default;
        payloadOffset = default;
        payloadLength = default;
        keyPhase = default;

        if (destinationConnectionId.Length > MaximumConnectionIdLength
            || material.EncryptionLevel != QuicTlsEncryptionLevel.OneRtt)
        {
            return false;
        }

        int sourceConnectionIdLength = sourceConnectionId.Length;
        int destinationConnectionIdLength = destinationConnectionId.Length;
        if (sourceConnectionIdLength > 0)
        {
            for (int packetNumberLength = 1; packetNumberLength <= ApplicationPacketNumberLength; packetNumberLength++)
            {
                if (TryOpenApplicationDataPacket(
                    protectedPacket,
                    material,
                    sourceConnectionIdLength,
                    packetNumberLength,
                    out openedPacket,
                    out payloadOffset,
                    out payloadLength,
                    out keyPhase))
                {
                    return true;
                }
            }

            if (sourceConnectionIdLength == destinationConnectionIdLength)
            {
                return false;
            }
        }

        for (int packetNumberLength = 1; packetNumberLength <= ApplicationPacketNumberLength; packetNumberLength++)
        {
            if (TryOpenApplicationDataPacket(
                protectedPacket,
                material,
                destinationConnectionIdLength,
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
            ReadOnlySpan<byte>.Empty,
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
        return TryOpenInitialPacket(
            protectedPacket,
            protection,
            requireZeroTokenLength: false,
            out openedPacket,
            out payloadOffset,
            out payloadLength);
    }

    /// <summary>
    /// Opens a protected Initial packet and returns the unprotected packet bytes plus payload layout.
    /// </summary>
    public bool TryOpenInitialPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicInitialPacketProtection protection,
        bool requireZeroTokenLength,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        openedPacket = [];
        payloadOffset = default;
        payloadLength = default;

        byte[] openedPacketBuffer = QuicBufferPool.RentBytes(protectedPacket.Length);
        try
        {
            if (!protection.TryOpen(protectedPacket, openedPacketBuffer, out int openedBytesWritten))
            {
                return false;
            }

            if (!TryParseInitialPayloadLayout(
                openedPacketBuffer.AsSpan(0, openedBytesWritten),
                requireZeroTokenLength,
                out payloadOffset,
                out payloadLength))
            {
                return false;
            }

            openedPacket = openedPacketBuffer.AsSpan(0, openedBytesWritten).ToArray();
            return true;
        }
        finally
        {
            QuicBufferPool.ReturnBytes(openedPacketBuffer);
        }
    }

    internal bool TryOpenOutboundInitialPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicInitialPacketProtection protection,
        out byte[] openedPacket,
        out int payloadOffset,
        out int payloadLength)
    {
        openedPacket = [];
        payloadOffset = default;
        payloadLength = default;

        byte[] openedPacketBuffer = QuicBufferPool.RentBytes(protectedPacket.Length);
        try
        {
            if (!protection.TryOpenOutbound(protectedPacket, openedPacketBuffer, out int openedBytesWritten))
            {
                return false;
            }

            if (!TryParseInitialPayloadLayout(
                openedPacketBuffer.AsSpan(0, openedBytesWritten),
                requireZeroTokenLength: false,
                out payloadOffset,
                out payloadLength))
            {
                return false;
            }

            openedPacket = openedPacketBuffer.AsSpan(0, openedBytesWritten).ToArray();
            return true;
        }
        finally
        {
            QuicBufferPool.ReturnBytes(openedPacketBuffer);
        }
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

    /// <summary>
    /// Formats and protects an Initial packet from prefix frame bytes plus a CRYPTO payload and its stream offset.
    /// </summary>
    public bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            initialDestinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            prefixFramePayload,
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

    public bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            initialDestinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            prefixFramePayload,
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
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketForHandshakeDestination(
            cryptoPayload,
            cryptoPayloadOffset,
            prefixFramePayload,
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

    internal bool TryBuildProtectedInitialPacketForHandshakeDestination(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacket(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            ReadOnlySpan<byte>.Empty,
            prefixFramePayload,
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
            ReadOnlySpan<byte>.Empty,
            protection,
            out _,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketCore(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            token,
            prefixFramePayload,
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
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketCore(
            cryptoPayload,
            cryptoPayloadOffset,
            destinationConnectionId,
            token,
            prefixFramePayload,
            protection,
            out packetNumber,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacketForRetransmission(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        return TryBuildProtectedInitialPacketForRetransmission(
            cryptoPayload,
            cryptoPayloadOffset,
            initialDestinationConnectionId,
            destinationConnectionId,
            sourceConnectionId,
            token,
            ReadOnlySpan<byte>.Empty,
            protection,
            out packetNumber,
            out protectedPacket);
    }

    internal bool TryBuildProtectedInitialPacketForRetransmission(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> initialDestinationConnectionId,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> sourceConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> prefixFramePayload,
        QuicInitialPacketProtection protection,
        out ulong packetNumber,
        out byte[] protectedPacket)
    {
        byte[] savedInitialDestinationConnectionId = this.initialDestinationConnectionId;
        byte[] savedDestinationConnectionId = this.destinationConnectionId;
        byte[] savedSourceConnectionId = this.sourceConnectionId;

        try
        {
            this.initialDestinationConnectionId = initialDestinationConnectionId.ToArray();
            this.destinationConnectionId = destinationConnectionId.ToArray();
            this.sourceConnectionId = sourceConnectionId.ToArray();
            return TryBuildProtectedInitialPacket(
                cryptoPayload,
                cryptoPayloadOffset,
                destinationConnectionId,
                token,
                prefixFramePayload,
                protection,
                out packetNumber,
                out protectedPacket);
        }
        finally
        {
            this.initialDestinationConnectionId = savedInitialDestinationConnectionId;
            this.destinationConnectionId = savedDestinationConnectionId;
            this.sourceConnectionId = savedSourceConnectionId;
        }
    }

    private bool TryBuildProtectedInitialPacketCore(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> prefixFramePayload,
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
                prefixFramePayload,
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
        ReadOnlySpan<byte> prefixFramePayload,
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

        try
        {
            if (prefixFramePayload.Length > int.MaxValue - cryptoFramePayloadLength)
            {
                return false;
            }

            int framePayloadLength = prefixFramePayload.Length + cryptoFramePayloadLength;
            int paddedPayloadLength = Math.Max(framePayloadLength, HandshakeMinimumProtectedPayloadLength);
            int packetNumberLength = HandshakePacketNumberLength;

            Span<byte> lengthFieldBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
            ulong lengthFieldValue = (ulong)(packetNumberLength + paddedPayloadLength + QuicInitialPacketProtection.AuthenticationTagLength);
            if (!QuicVariableLengthInteger.TryFormat(lengthFieldValue, lengthFieldBuffer, out int lengthFieldBytesWritten))
            {
                return false;
            }

            byte[] versionSpecificData = QuicBufferPool.RentBytes(lengthFieldBytesWritten + packetNumberLength + paddedPayloadLength);
            try
            {
                int versionSpecificDataIndex = 0;

                lengthFieldBuffer[..lengthFieldBytesWritten].CopyTo(versionSpecificData);
                versionSpecificDataIndex += lengthFieldBytesWritten;

                BinaryPrimitives.WriteUInt32BigEndian(
                    versionSpecificData.AsSpan(versionSpecificDataIndex, packetNumberLength),
                    unchecked((uint)nextPacketNumber));
                versionSpecificDataIndex += packetNumberLength;

                prefixFramePayload.CopyTo(versionSpecificData.AsSpan(versionSpecificDataIndex));
                versionSpecificDataIndex += prefixFramePayload.Length;

                cryptoFramePayload.AsSpan(0, cryptoFramePayloadLength).CopyTo(versionSpecificData.AsSpan(versionSpecificDataIndex));
                versionSpecificDataIndex += cryptoFramePayloadLength;

                if (paddedPayloadLength > framePayloadLength)
                {
                    versionSpecificData.AsSpan(versionSpecificDataIndex, paddedPayloadLength - framePayloadLength).Fill(0);
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
                    versionSpecificData.AsSpan(0, lengthFieldBytesWritten + packetNumberLength + paddedPayloadLength),
                    includeTokenLengthField: false);

                nextPacketNumber = nextPacketNumber == ulong.MaxValue ? 0 : nextPacketNumber + 1;
                return true;
            }
            finally
            {
                QuicBufferPool.ReturnBytes(versionSpecificData);
            }
        }
        finally
        {
            QuicBufferPool.ReturnBytes(cryptoFramePayload);
        }
    }

    private bool TryBuildInitialPlaintextPacket(
        ReadOnlySpan<byte> cryptoPayload,
        ulong cryptoPayloadOffset,
        ReadOnlySpan<byte> destinationConnectionId,
        ReadOnlySpan<byte> token,
        ReadOnlySpan<byte> prefixFramePayload,
        out ulong packetNumber,
        out byte[] plaintextPacket)
    {
        plaintextPacket = [];
        packetNumber = default;

        if (sourceConnectionId.Length == 0)
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

        try
        {
            if (prefixFramePayload.Length > int.MaxValue - cryptoFramePayloadLength)
            {
                return false;
            }

            int framePayloadLength = prefixFramePayload.Length + cryptoFramePayloadLength;
            int paddedPayloadLength = Math.Max(framePayloadLength, HandshakeMinimumProtectedPayloadLength);
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

            byte[] versionSpecificData = QuicBufferPool.RentBytes(lengthFieldBytesWritten + packetNumberLength + paddedPayloadLength);
            try
            {
                int versionSpecificDataIndex = 0;

                lengthFieldBuffer[..lengthFieldBytesWritten].CopyTo(versionSpecificData);
                versionSpecificDataIndex += lengthFieldBytesWritten;

                BinaryPrimitives.WriteUInt32BigEndian(
                    versionSpecificData.AsSpan(versionSpecificDataIndex, packetNumberLength),
                    unchecked((uint)nextPacketNumber));
                versionSpecificDataIndex += packetNumberLength;

                prefixFramePayload.CopyTo(versionSpecificData.AsSpan(versionSpecificDataIndex));
                versionSpecificDataIndex += prefixFramePayload.Length;

                cryptoFramePayload.AsSpan(0, cryptoFramePayloadLength).CopyTo(versionSpecificData.AsSpan(versionSpecificDataIndex));
                versionSpecificDataIndex += cryptoFramePayloadLength;

                if (paddedPayloadLength > framePayloadLength)
                {
                    versionSpecificData.AsSpan(versionSpecificDataIndex, paddedPayloadLength - framePayloadLength).Fill(0);
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
                    versionSpecificData.AsSpan(0, lengthFieldBytesWritten + packetNumberLength + paddedPayloadLength),
                    includeTokenLengthField: true);

                nextPacketNumber = nextPacketNumber == ulong.MaxValue ? 0 : nextPacketNumber + 1;
                return true;
            }
            finally
            {
                QuicBufferPool.ReturnBytes(versionSpecificData);
            }
        }
        finally
        {
            QuicBufferPool.ReturnBytes(cryptoFramePayload);
        }
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

        byte[] buffer = QuicBufferPool.RentBytes(cryptoPayload.Length + CryptoFramePayloadBufferOverhead);
        try
        {
            if (!QuicFrameCodec.TryFormatCryptoFrame(
                new QuicCryptoFrame(cryptoPayloadOffset, cryptoPayload),
                buffer,
                out int bytesWritten))
            {
                QuicBufferPool.ReturnBytes(buffer);
                return false;
            }

            cryptoFramePayload = buffer;
            cryptoFramePayloadLength = bytesWritten;
            return true;
        }
        catch
        {
            QuicBufferPool.ReturnBytes(buffer);
            throw;
        }
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
        Span<byte> tokenLengthBuffer = stackalloc byte[QuicVariableLengthInteger.MaxEncodedLength];
        int tokenLengthBytesWritten = 0;
        if (includeTokenLengthField)
        {
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
            tokenLengthBuffer[..tokenLengthBytesWritten].CopyTo(packet.AsSpan(versionSpecificDataOffset));
            token.CopyTo(packet.AsSpan(versionSpecificDataOffset + tokenLengthBytesWritten));
            versionSpecificDataOffset += tokenLengthBytesWritten + token.Length;
        }

        sourceConnectionId.CopyTo(packet.AsSpan(sourceConnectionIdLengthOffset + 1));
        versionSpecificData.CopyTo(packet.AsSpan(versionSpecificDataOffset));

        return packet;
    }

    private static bool TryParseInitialPayloadLayout(
        ReadOnlySpan<byte> openedPacket,
        bool requireZeroTokenLength,
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
            || !QuicVariableLengthInteger.TryParse(versionSpecificData, out ulong tokenLength, out int tokenLengthBytes)
            || (requireZeroTokenLength && tokenLength != 0))
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

        if (destinationConnectionId.Length > MaximumConnectionIdLength
            || applicationPayload.Length > int.MaxValue - 1 - destinationConnectionId.Length - packetNumberLength - ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        int paddedPayloadLength = Math.Max(applicationPayload.Length, ApplicationMinimumProtectedPayloadLength);
        packetNumberOffset = 1 + destinationConnectionId.Length;
        bool spinBitEnabled = enableRandomizedSpinBitSelection && !ShouldDisableSpinBit(destinationConnectionId);

        byte[] packet = new byte[packetNumberOffset + packetNumberLength + paddedPayloadLength];
        packet[0] = (byte)(
            QuicPacketHeaderBits.FixedBitMask
            | (spinBitEnabled ? QuicPacketHeaderBits.SpinBitMask : 0)
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

    private bool TryBuildApplicationDataPlaintextPacket(
        ReadOnlySpan<byte> applicationPayload,
        bool keyPhase,
        out QuicBufferLease plaintextPacket,
        out int packetNumberOffset,
        out int packetNumberLength)
    {
        plaintextPacket = default;
        packetNumberOffset = default;
        packetNumberLength = ApplicationPacketNumberLength;

        if (destinationConnectionId.Length > MaximumConnectionIdLength
            || applicationPayload.Length > int.MaxValue - 1 - destinationConnectionId.Length - packetNumberLength - ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        int paddedPayloadLength = Math.Max(applicationPayload.Length, ApplicationMinimumProtectedPayloadLength);
        packetNumberOffset = 1 + destinationConnectionId.Length;
        bool spinBitEnabled = enableRandomizedSpinBitSelection && !ShouldDisableSpinBit(destinationConnectionId);

        plaintextPacket = QuicBufferPool.RentLease(packetNumberOffset + packetNumberLength + paddedPayloadLength);
        try
        {
            Span<byte> packet = plaintextPacket.Span;
            packet[0] = (byte)(
                QuicPacketHeaderBits.FixedBitMask
                | (spinBitEnabled ? QuicPacketHeaderBits.SpinBitMask : 0)
                | (keyPhase ? QuicPacketHeaderBits.KeyPhaseBitMask : 0)
                | (packetNumberLength - 1));
            destinationConnectionId.CopyTo(packet[1..]);

            BinaryPrimitives.WriteUInt32BigEndian(
                packet.Slice(packetNumberOffset, packetNumberLength),
                unchecked((uint)nextApplicationPacketNumber));

            applicationPayload.CopyTo(packet.Slice(packetNumberOffset + packetNumberLength));

            if (paddedPayloadLength > applicationPayload.Length)
            {
                packet.Slice(
                    packetNumberOffset + packetNumberLength + applicationPayload.Length,
                    paddedPayloadLength - applicationPayload.Length).Fill(0);
            }

            plaintextPacket.SetLength(packetNumberOffset + packetNumberLength + paddedPayloadLength);
            return true;
        }
        catch
        {
            plaintextPacket.Dispose();
            plaintextPacket = default;
            return false;
        }
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

        ReadOnlySpan<byte> effectiveDestinationConnectionId = destinationConnectionId.Length == 0
            ? initialDestinationConnectionId
            : destinationConnectionId;

        if (effectiveDestinationConnectionId.Length == 0
            || sourceConnectionId.Length == 0
            || applicationPayload.Length > int.MaxValue - LongHeaderFixedPrefixLength - LongHeaderConnectionIdLengthFieldsLength - effectiveDestinationConnectionId.Length - sourceConnectionId.Length - packetNumberLength - ApplicationMinimumProtectedPayloadLength)
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
            + effectiveDestinationConnectionId.Length
            + 1
            + sourceConnectionId.Length;
        if (longHeaderPrefixLength > int.MaxValue - lengthFieldBytes - packetNumberLength - paddedPayloadLength)
        {
            return false;
        }

        packetNumberOffset = longHeaderPrefixLength + lengthFieldBytes;

        byte[] versionSpecificData = QuicBufferPool.RentBytes(lengthFieldBytes + packetNumberLength + paddedPayloadLength);
        try
        {
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
                effectiveDestinationConnectionId,
                sourceConnectionId,
                token: ReadOnlySpan<byte>.Empty,
                versionSpecificData.AsSpan(0, lengthFieldBytes + packetNumberLength + paddedPayloadLength),
                includeTokenLengthField: false);
            return true;
        }
        finally
        {
            QuicBufferPool.ReturnBytes(versionSpecificData);
        }
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

    private bool TryProtectApplicationDataPacket(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> plaintextPacket,
        int packetNumberOffset,
        int packetNumberLength,
        out QuicBufferLease protectedPacket)
    {
        protectedPacket = default;

        if (!TryValidatePacketProtectionMaterial(material))
        {
            return false;
        }

        int plaintextPayloadLength = plaintextPacket.Length - packetNumberOffset - packetNumberLength;
        if (plaintextPayloadLength < ApplicationMinimumProtectedPayloadLength)
        {
            return false;
        }

        protectedPacket = QuicBufferPool.RentLease(plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength);
        bool success = false;
        try
        {
            Span<byte> protectedPacketBuffer = protectedPacket.Span;
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
                protectedPacketBuffer.Slice(packetNumberOffset + packetNumberLength, plaintextPayloadLength),
                protectedPacketBuffer.Slice(plaintextPacket.Length, QuicInitialPacketProtection.AuthenticationTagLength),
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

            protectedPacket.SetLength(plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength);
            success = true;
            return true;
        }
        finally
        {
            if (!success)
            {
                protectedPacket.Dispose();
                protectedPacket = default;
            }
        }
    }

    private bool TryOpenApplicationDataPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        int connectionIdLength,
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
            || connectionIdLength < 0
            || packetNumberLength < 1
            || packetNumberLength > ApplicationPacketNumberLength
            || connectionIdLength > MaximumConnectionIdLength)
        {
            return false;
        }

        int packetNumberOffset = 1 + connectionIdLength;
        int ciphertextPayloadLength = protectedPacket.Length - packetNumberOffset - packetNumberLength - QuicInitialPacketProtection.AuthenticationTagLength;
        // Incoming short-header packets can legitimately carry tiny payloads, such as a FIN-only STREAM frame.
        if (ciphertextPayloadLength < 0)
        {
            return false;
        }

        int sampleOffset = packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset;
        if (protectedPacket.Length < sampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength)
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!material.TryGenerateHeaderProtectionMask(
            protectedPacket.Slice(sampleOffset, QuicInitialPacketProtection.HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        byte unmaskedFirstByte = (byte)(protectedPacket[0] ^ (mask[0] & QuicPacketHeaderBits.ShortTypeSpecificBitsMask));
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

    private bool TryOpenApplicationDataPacket(
        ReadOnlySpan<byte> protectedPacket,
        QuicTlsPacketProtectionMaterial material,
        int connectionIdLength,
        int packetNumberLength,
        out QuicBufferLease openedPacket,
        out int payloadOffset,
        out int payloadLength,
        out bool keyPhase)
    {
        openedPacket = default;
        payloadOffset = default;
        payloadLength = default;
        keyPhase = default;

        if (!TryValidatePacketProtectionMaterial(material)
            || connectionIdLength < 0
            || packetNumberLength < 1
            || packetNumberLength > ApplicationPacketNumberLength
            || connectionIdLength > MaximumConnectionIdLength)
        {
            return false;
        }

        int packetNumberOffset = 1 + connectionIdLength;
        int ciphertextPayloadLength = protectedPacket.Length - packetNumberOffset - packetNumberLength - QuicInitialPacketProtection.AuthenticationTagLength;
        // Incoming short-header packets can legitimately carry tiny payloads, such as a FIN-only STREAM frame.
        if (ciphertextPayloadLength < 0)
        {
            return false;
        }

        int sampleOffset = packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset;
        if (protectedPacket.Length < sampleOffset + QuicInitialPacketProtection.HeaderProtectionSampleLength)
        {
            return false;
        }

        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!material.TryGenerateHeaderProtectionMask(
            protectedPacket.Slice(sampleOffset, QuicInitialPacketProtection.HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        byte unmaskedFirstByte = (byte)(protectedPacket[0] ^ (mask[0] & QuicPacketHeaderBits.ShortTypeSpecificBitsMask));
        if ((unmaskedFirstByte & QuicPacketHeaderBits.HeaderFormBitMask) != 0
            || (unmaskedFirstByte & QuicPacketHeaderBits.FixedBitMask) == 0
            || ((unmaskedFirstByte & QuicPacketHeaderBits.PacketNumberLengthBitsMask) + 1) != packetNumberLength
            || (unmaskedFirstByte & QuicPacketHeaderBits.ShortReservedBitsMask) != 0)
        {
            return false;
        }

        bool observedKeyPhase = (unmaskedFirstByte & QuicPacketHeaderBits.KeyPhaseBitMask) != 0;

        int unprotectedPacketLength = protectedPacket.Length - QuicInitialPacketProtection.AuthenticationTagLength;
        openedPacket = QuicBufferPool.RentLease(unprotectedPacketLength);
        bool success = false;
        try
        {
            Span<byte> openedPacketBuffer = openedPacket.Span;
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
                openedPacketBuffer.Slice(packetNumberOffset + packetNumberLength, ciphertextPayloadLength),
                openedPacketBuffer[..(packetNumberOffset + packetNumberLength)]))
            {
                return false;
            }

            // Only publish the observed Key Phase after the packet authenticates successfully.
            keyPhase = observedKeyPhase;
            openedPacket.SetLength(unprotectedPacketLength);
            payloadOffset = packetNumberOffset + packetNumberLength;
            payloadLength = ciphertextPayloadLength;
            success = true;
            return true;
        }
        finally
        {
            if (!success)
            {
                openedPacket.Dispose();
                openedPacket = default;
            }
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
        return material.TryEncryptPacketPayload(nonce, plaintext, ciphertext, tag, associatedData);
    }

    private static bool TryDecryptPacketPayload(
        QuicTlsPacketProtectionMaterial material,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> tag,
        Span<byte> plaintext,
        ReadOnlySpan<byte> associatedData)
    {
        return material.TryDecryptPacketPayload(nonce, ciphertext, tag, plaintext, associatedData);
    }

    private static bool TryApplyHeaderProtection(
        QuicTlsPacketProtectionMaterial material,
        Span<byte> packet,
        int packetNumberOffset,
        int packetNumberLength)
    {
        Span<byte> mask = stackalloc byte[HeaderProtectionMaskLength];
        if (!material.TryGenerateHeaderProtectionMask(
            packet.Slice(packetNumberOffset + QuicInitialPacketProtection.HeaderProtectionSampleOffset, QuicInitialPacketProtection.HeaderProtectionSampleLength),
            mask))
        {
            return false;
        }

        packet[0] ^= (byte)(mask[0] & QuicPacketHeaderBits.ShortTypeSpecificBitsMask);
        for (int i = 0; i < packetNumberLength; i++)
        {
            packet[packetNumberOffset + i] ^= mask[1 + i];
        }

        return true;
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

    private static bool ShouldDisableSpinBit(ReadOnlySpan<byte> connectionId)
    {
        return connectionId.IsEmpty || (connectionId[0] & SpinBitSelectionMask) == 0;
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
