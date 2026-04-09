namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0008")]
public sealed class REQ_QUIC_RFC9001_S3_0008
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeOwnsTlsProducedHandshakeBytesBeforePacketization()
    {
        QuicConnectionRuntime runtime = CreateRuntime();
        byte[] tlsHandshakeBytes = [0x01, 0x02, 0x03, 0x04];

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 5,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.Handshake,
                    CryptoDataOffset: 0,
                    CryptoData: tlsHandshakeBytes)),
            nowTicks: 5).StateChanged);

        tlsHandshakeBytes[0] = 0xFF;

        Span<byte> dequeuedCryptoBytes = stackalloc byte[4];
        Assert.True(runtime.TlsState.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            dequeuedCryptoBytes,
            out int bytesWritten));

        Assert.Equal(4, bytesWritten);
        Assert.True(new byte[] { 0x01, 0x02, 0x03, 0x04 }.AsSpan().SequenceEqual(dequeuedCryptoBytes[..bytesWritten]));
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsOneRttCryptoDataAvailableUpdates()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.OneRtt,
                    CryptoDataOffset: 0,
                    CryptoData: new byte[] { 0xAA })),
            nowTicks: 10);

        Assert.False(result.StateChanged);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Span<byte> dequeuedCryptoBytes = stackalloc byte[1];
        Assert.False(runtime.TlsState.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            dequeuedCryptoBytes,
            out _));
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }
}
