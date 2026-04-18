namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S17P2P5P3-0003")]
public sealed class REQ_QUIC_RFC9000_S17P2P5P3_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ClientRetryReplayInitialPacketsPreserveTheOriginalHandshakeMessageBytes()
    {
        using QuicConnectionRuntime clientRuntime = QuicS17P2P5P2TestSupport.CreateBootstrappedClientRuntime();
        byte[] originalClientHelloBytes = QuicResumptionClientHelloTestSupport.GetInitialBootstrapClientHelloBytes(clientRuntime);

        QuicConnectionTransitionResult retryResult = clientRuntime.Transition(
            QuicS17P2P5P2TestSupport.CreateRetryReceivedEvent(1),
            nowTicks: 1);

        QuicS17P2P5P3TestSupport.RetryReplayInitialPacket[] replayPackets =
            QuicS17P2P5P3TestSupport.ReadRetryReplayInitialPackets(
                retryResult,
                QuicS17P2P5P3TestSupport.CreateServerProtection());

        Assert.NotEmpty(replayPackets);

        ulong expectedOffset = 0;
        foreach (QuicS17P2P5P3TestSupport.RetryReplayInitialPacket replayPacket in replayPackets)
        {
            Assert.Equal(expectedOffset, replayPacket.CryptoOffset);
            Assert.True(originalClientHelloBytes.AsSpan(
                checked((int)replayPacket.CryptoOffset),
                replayPacket.CryptoPayload.Length).SequenceEqual(replayPacket.CryptoPayload));
            expectedOffset += (ulong)replayPacket.CryptoPayload.Length;
        }

        Assert.Equal((ulong)originalClientHelloBytes.Length, expectedOffset);
    }
}
