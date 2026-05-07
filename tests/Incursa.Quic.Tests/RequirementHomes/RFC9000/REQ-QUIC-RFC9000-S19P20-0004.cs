namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P20-0004")]
public sealed class REQ_QUIC_RFC9000_S19P20_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ActiveClientRuntimeDoesNotSendHandshakeDoneFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, QuicS19P20HandshakeDoneTestSupport.IsHandshakeDonePlaintext);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ServerPeerHandshakeCompletionSendsTheHandshakeDoneFrame()
    {
        using QuicConnectionRuntime runtime = QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();

        QuicConnectionTransitionResult result = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(
            runtime,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        QuicConnectionSentPacket sentPacket = Assert.Single(
            runtime.SendRuntime.SentPackets.Values,
            QuicS19P20HandshakeDoneTestSupport.IsHandshakeDonePlaintext);
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, sentPacket.PacketNumberSpace);
        Assert.True(sentPacket.AckEliciting);
        Assert.True(sentPacket.Retransmittable);
    }
}
