namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S4-0005")]
public sealed class REQ_QUIC_RFC9001_S4_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeSurfacesInboundCryptoBytesWithoutConfirmingHandshake()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        Assert.True(runtime.Transition(
            new QuicConnectionCryptoFrameReceivedEvent(
                ObservedAtTicks: 5,
                QuicTlsEncryptionLevel.Initial,
                Offset: 0,
                CryptoData: new byte[] { 0x01, 0x02, 0x03 }),
            nowTicks: 5).StateChanged);

        Span<byte> surfacedCryptoBytes = stackalloc byte[3];
        Assert.True(runtime.TlsState.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Initial,
            surfacedCryptoBytes,
            out int bytesWritten));

        Assert.Equal(3, bytesWritten);
        Assert.True(new byte[] { 0x01, 0x02, 0x03 }.AsSpan().SequenceEqual(surfacedCryptoBytes[..bytesWritten]));
        Assert.False(runtime.HandshakeConfirmed);
        Assert.False(runtime.TlsState.HandshakeConfirmed);
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }
}
