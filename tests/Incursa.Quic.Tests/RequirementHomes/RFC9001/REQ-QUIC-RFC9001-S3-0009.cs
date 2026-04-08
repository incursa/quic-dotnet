namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0009")]
public sealed class REQ_QUIC_RFC9001_S3_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeReassemblesOutOfOrderCryptoFramesByOffset()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        Assert.True(runtime.Transition(
            new QuicConnectionCryptoFrameReceivedEvent(
                ObservedAtTicks: 1,
                QuicTlsEncryptionLevel.Handshake,
                Offset: 4,
                CryptoData: new byte[] { 0x44, 0x45 }),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionCryptoFrameReceivedEvent(
                ObservedAtTicks: 2,
                QuicTlsEncryptionLevel.Handshake,
                Offset: 0,
                CryptoData: new byte[] { 0x10, 0x11 }),
            nowTicks: 2).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionCryptoFrameReceivedEvent(
                ObservedAtTicks: 3,
                QuicTlsEncryptionLevel.Handshake,
                Offset: 2,
                CryptoData: new byte[] { 0x22, 0x33 }),
            nowTicks: 3).StateChanged);

        Span<byte> assembledCryptoBytes = stackalloc byte[6];
        Assert.True(runtime.TlsState.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            assembledCryptoBytes,
            out int bytesWritten));

        Assert.Equal(6, bytesWritten);
        Assert.True(new byte[] { 0x10, 0x11, 0x22, 0x33, 0x44, 0x45 }.AsSpan().SequenceEqual(assembledCryptoBytes[..bytesWritten]));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsOverflowingCryptoFrameOffsets()
    {
        QuicConnectionRuntime runtime = CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionCryptoFrameReceivedEvent(
                ObservedAtTicks: 9,
                QuicTlsEncryptionLevel.Handshake,
                Offset: ulong.MaxValue,
                CryptoData: new byte[] { 0xAA }),
            nowTicks: 9);

        Assert.False(result.StateChanged);
        Span<byte> probe = stackalloc byte[1];
        Assert.False(runtime.TlsState.TryDequeueIncomingCryptoData(
            QuicTlsEncryptionLevel.Handshake,
            probe,
            out _));
    }

    private static QuicConnectionRuntime CreateRuntime()
    {
        return new QuicConnectionRuntime(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0));
    }
}
