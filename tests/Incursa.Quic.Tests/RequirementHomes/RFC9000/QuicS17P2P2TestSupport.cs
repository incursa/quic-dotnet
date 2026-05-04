namespace Incursa.Quic.Tests;

internal static class QuicS17P2P2TestSupport
{
    internal static readonly byte[] InitialDestinationConnectionId = QuicS17P1TestSupport.InitialDestinationConnectionId;

    internal static readonly byte[] InitialSourceConnectionId = QuicS17P1TestSupport.InitialSourceConnectionId;

    internal static readonly byte[] ServerSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    internal static QuicHandshakeFlowCoordinator CreateClientCoordinator()
    {
        return new(InitialDestinationConnectionId, InitialSourceConnectionId);
    }

    internal static QuicHandshakeFlowCoordinator CreateServerCoordinator()
    {
        return new(InitialDestinationConnectionId, ServerSourceConnectionId);
    }

    internal static QuicConnectionRuntime CreateServerRuntime(
        byte[]? initialDestinationConnectionId = null,
        long clockTicks = 0)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(clockTicks),
            currentProbeTimeoutMicros: 100,
            tlsRole: QuicTlsRole.Server);

        Assert.True(runtime.TryConfigureInitialPacketProtection(
            initialDestinationConnectionId ?? InitialDestinationConnectionId));
        return runtime;
    }

    internal static byte BuildInitialHeaderControlBits(int packetNumberLength = 2, byte reservedBits = 0x00)
    {
        Assert.InRange(packetNumberLength, 1, 4);
        Assert.InRange((int)reservedBits, 0, 3);

        return (byte)(QuicPacketHeaderBits.FixedBitMask
            | (QuicLongPacketTypeBits.Initial << QuicPacketHeaderBits.LongPacketTypeBitsShift)
            | ((reservedBits & 0x03) << QuicPacketHeaderBits.LongReservedBitsShift)
            | ((packetNumberLength - 1) & QuicPacketHeaderBits.PacketNumberLengthBitsMask));
    }

    internal static byte[] BuildInitialPacket(
        int packetNumberLength = 2,
        byte reservedBits = 0x00,
        uint version = QuicVersionNegotiation.Version1,
        byte[]? destinationConnectionId = null,
        byte[]? sourceConnectionId = null,
        byte[]? token = null,
        byte[]? protectedPayload = null)
    {
        return QuicHeaderTestData.BuildLongHeader(
            BuildInitialHeaderControlBits(packetNumberLength, reservedBits),
            version,
            destinationConnectionId ?? [0x10, 0x11],
            sourceConnectionId ?? [0x20],
            BuildInitialVersionSpecificData(packetNumberLength, token, protectedPayload));
    }

    internal static byte[] BuildInitialVersionSpecificData(
        int packetNumberLength,
        byte[]? token = null,
        byte[]? protectedPayload = null)
    {
        return QuicHeaderTestData.BuildInitialVersionSpecificData(
            token ?? [],
            CreatePacketNumber(packetNumberLength),
            protectedPayload ?? [0xAA]);
    }

    internal static byte[] CreatePacketNumber(int packetNumberLength)
    {
        Assert.InRange(packetNumberLength, 1, 4);

        byte[] packetNumber = new byte[packetNumberLength];
        for (int index = 0; index < packetNumber.Length; index++)
        {
            packetNumber[index] = (byte)(index + 1);
        }

        return packetNumber;
    }

    internal static byte[] CreateSequentialBytes(byte startValue, int length)
    {
        byte[] bytes = new byte[length];
        for (int index = 0; index < bytes.Length; index++)
        {
            bytes[index] = unchecked((byte)(startValue + index));
        }

        return bytes;
    }

    internal static byte[] CreateProtectedClientInitialPacket(
        ReadOnlySpan<byte> plaintextPayload,
        byte[]? initialDestinationConnectionId = null,
        ReadOnlySpan<byte> token = default)
    {
        byte[] destinationConnectionId = initialDestinationConnectionId ?? InitialDestinationConnectionId;
        byte[] paddedPlaintextPayload = new byte[Math.Max(plaintextPayload.Length, 24)];
        plaintextPayload.CopyTo(paddedPlaintextPayload);

        byte[] plaintextPacket = QuicInitialPacketProtectionTestData.BuildInitialPlaintextPacket(
            destinationConnectionId,
            InitialSourceConnectionId,
            token,
            packetNumber: [0x01],
            paddedPlaintextPayload);

        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Client,
            destinationConnectionId,
            out QuicInitialPacketProtection protection));

        byte[] protectedPacket = new byte[plaintextPacket.Length + QuicInitialPacketProtection.AuthenticationTagLength];
        Assert.True(protection.TryProtect(plaintextPacket, protectedPacket, out int bytesWritten));
        Assert.Equal(protectedPacket.Length, bytesWritten);

        return protectedPacket;
    }

    internal static bool IsInitialPacket(ReadOnlySpan<byte> packet)
    {
        return QuicPacketParser.TryParseLongHeader(packet, out QuicLongHeaderPacket longHeader)
            && longHeader.Version == QuicVersionNegotiation.Version1
            && longHeader.LongPacketTypeBits == QuicLongPacketTypeBits.Initial;
    }

    internal static void AssertInitialTokenLength(ReadOnlySpan<byte> openedPacket, ulong expectedTokenLength)
    {
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out _,
            out _,
            out ReadOnlySpan<byte> versionSpecificData));
        Assert.Equal(QuicVersionNegotiation.Version1, version);
        Assert.Equal(
            QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));

        Assert.True(QuicVariableLengthInteger.TryParse(
            versionSpecificData,
            out ulong tokenLength,
            out _));
        Assert.Equal(expectedTokenLength, tokenLength);
    }

    internal static void AssertOpenedInitialPacketContainsCryptoPayload(
        ReadOnlySpan<byte> openedPacket,
        int payloadOffset,
        int payloadLength,
        ReadOnlySpan<byte> expectedCryptoPayload,
        ulong expectedCryptoOffset)
    {
        Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
            openedPacket,
            out byte headerControlBits,
            out uint version,
            out _,
            out _,
            out _));
        Assert.Equal((uint)1, version);
        Assert.Equal(
            (byte)QuicLongPacketTypeBits.Initial,
            (byte)((headerControlBits & QuicPacketHeaderBits.LongPacketTypeBitsMask) >> QuicPacketHeaderBits.LongPacketTypeBitsShift));

        Assert.True(QuicFrameCodec.TryParseCryptoFrame(
            openedPacket.Slice(payloadOffset, payloadLength),
            out QuicCryptoFrame parsedFrame,
            out int bytesConsumed));

        byte[] expectedFrame = QuicFrameTestData.BuildCryptoFrame(new QuicCryptoFrame(expectedCryptoOffset, expectedCryptoPayload));
        Assert.Equal(expectedFrame.Length, bytesConsumed);
        Assert.Equal(expectedCryptoOffset, parsedFrame.Offset);
        Assert.True(parsedFrame.CryptoData.SequenceEqual(expectedCryptoPayload));
        Assert.True(expectedFrame.AsSpan().SequenceEqual(openedPacket.Slice(payloadOffset, bytesConsumed)));
    }
}
