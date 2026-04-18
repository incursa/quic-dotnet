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
