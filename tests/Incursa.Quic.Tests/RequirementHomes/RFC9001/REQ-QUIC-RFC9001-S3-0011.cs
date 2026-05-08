namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9001-S3-0011")]
public sealed class REQ_QUIC_RFC9001_S3_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeRejectsTlsApplicationDataRecordsOnCryptoPath()
    {
        QuicConnectionRuntime runtime = QuicRfc9001TailProofTestSupport.CreateRuntime();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 10,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.CryptoDataAvailable,
                    QuicTlsEncryptionLevel.OneRtt,
                    CryptoDataOffset: 0,
                    CryptoData: new byte[] { 0x17, 0x03, 0x03, 0x00, 0x00 })),
            nowTicks: 10);

        Assert.False(result.StateChanged);
        Span<byte> dequeuedCryptoBytes = stackalloc byte[5];
        Assert.False(runtime.TlsState.TryDequeueOutgoingCryptoData(
            QuicTlsEncryptionLevel.OneRtt,
            dequeuedCryptoBytes,
            out _));
    }
}
