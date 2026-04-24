namespace Incursa.Quic.Tests;

internal static class QuicS17P2P5P3TestSupport
{
    internal static QuicInitialPacketProtection CreateServerProtection()
    {
        Assert.True(QuicInitialPacketProtection.TryCreate(
            QuicTlsRole.Server,
            QuicS17P2P5P2TestSupport.RetrySourceConnectionId,
            out QuicInitialPacketProtection serverProtection));

        return serverProtection;
    }

    internal static RetryReplayInitialPacket[] ReadRetryReplayInitialPackets(
        QuicConnectionTransitionResult retryResult,
        QuicInitialPacketProtection serverProtection)
    {
        List<RetryReplayInitialPacket> packets = [];

        foreach (QuicConnectionSendDatagramEffect sendEffect in QuicS17P2P3TestSupport.GetInitialSendEffects(retryResult.Effects))
        {
            QuicHandshakeFlowCoordinator coordinator = new();
            Assert.True(coordinator.TryOpenInitialPacket(
                sendEffect.Datagram.Span,
                serverProtection,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            Assert.True(QuicPacketParsing.TryParseLongHeaderFields(
                openedPacket,
                out _,
                out _,
                out ReadOnlySpan<byte> openedDestinationConnectionId,
                out _,
                out ReadOnlySpan<byte> versionSpecificData));

            Assert.True(QuicVariableLengthInteger.TryParse(
                versionSpecificData,
                out ulong tokenLength,
                out int tokenLengthBytesConsumed));
            Assert.True(tokenLength <= (ulong)(versionSpecificData.Length - tokenLengthBytesConsumed));

            byte[] retryToken = versionSpecificData.Slice(tokenLengthBytesConsumed, checked((int)tokenLength)).ToArray();
            Assert.True(QuicFrameCodec.TryParseCryptoFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out QuicCryptoFrame cryptoFrame,
                out _));

            packets.Add(new RetryReplayInitialPacket(
                openedPacket,
                openedDestinationConnectionId.ToArray(),
                retryToken,
                cryptoFrame.Offset,
                cryptoFrame.CryptoData.ToArray()));
        }

        return packets.ToArray();
    }

    internal sealed record RetryReplayInitialPacket(
        byte[] OpenedPacket,
        byte[] DestinationConnectionId,
        byte[] Token,
        ulong CryptoOffset,
        byte[] CryptoPayload);
}
