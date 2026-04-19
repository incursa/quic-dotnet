namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P3-0002")]
public sealed class REQ_QUIC_RFC9000_S9P3P3_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathChallengeFramesOnTheActivePathAreAnsweredWithPathResponseFrames()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] challengeData =
        [
            0x10, 0x11, 0x12, 0x13,
            0x14, 0x15, 0x16, 0x17,
        ];
        byte[] applicationPayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        Assert.True(runtime.TlsState.TryGetPacketProtectionMaterial(
            QuicTlsEncryptionLevel.OneRtt,
            out QuicTlsPacketProtectionMaterial material));

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x01],
            applicationPayload,
            material,
            declaredPacketNumberLength: 4);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                activePath,
                protectedPacket),
            nowTicks: 9);

        QuicConnectionSendDatagramEffect send = Assert.Single(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(activePath, send.PathIdentity);
        Assert.True(QuicFrameCodec.TryParsePathResponseFrame(
            send.Datagram.Span,
            out QuicPathResponseFrame parsedResponse,
            out int bytesConsumed));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
        Assert.True(challengeData.AsSpan().SequenceEqual(parsedResponse.Data));
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
