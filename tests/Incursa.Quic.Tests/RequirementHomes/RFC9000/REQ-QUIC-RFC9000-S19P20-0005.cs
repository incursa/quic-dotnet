namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P20-0005")]
public sealed class REQ_QUIC_RFC9000_S19P20_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ServerSendsHandshakeDoneWhenThePeerHandshakeCompletes()
    {
        using QuicConnectionRuntime runtime = QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();

        QuicConnectionTransitionResult result = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(
            runtime,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        QuicConnectionSentPacket sentPacket = Assert.Single(
            runtime.SendRuntime.SentPackets.Values,
            QuicS19P20HandshakeDoneTestSupport.IsHandshakeDonePlaintext);
        Assert.Equal(QuicFrameTestData.BuildHandshakeDoneFrame(), sentPacket.PlaintextPayload.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ServerDoesNotSendHandshakeDoneWhenOneRttKeysArriveBeforePeerHandshakeCompletion()
    {
        using QuicConnectionRuntime runtime = QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 1,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.KeysAvailable,
                    EncryptionLevel: QuicTlsEncryptionLevel.OneRtt)),
            nowTicks: 1);

        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets.Values, QuicS19P20HandshakeDoneTestSupport.IsHandshakeDonePlaintext);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ServerSendsHandshakeDoneOnlyOnceAcrossRepeatedCompletionSignals()
    {
        using QuicConnectionRuntime runtime = QuicS19P20HandshakeDoneTestSupport.CreateServerRuntimeReadyToEvaluateHandshakeDoneSend();

        QuicConnectionTransitionResult firstResult = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(
            runtime,
            observedAtTicks: 1);
        QuicConnectionTransitionResult secondResult = QuicS19P20HandshakeDoneTestSupport.CompletePeerHandshakeTranscript(
            runtime,
            observedAtTicks: 2);

        Assert.True(firstResult.StateChanged);
        Assert.Single(
            runtime.SendRuntime.SentPackets.Values,
            QuicS19P20HandshakeDoneTestSupport.IsHandshakeDonePlaintext);
        Assert.DoesNotContain(secondResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }
}
