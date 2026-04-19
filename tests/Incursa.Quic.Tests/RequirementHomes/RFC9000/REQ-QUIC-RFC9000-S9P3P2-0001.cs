namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P2-0001")]
public sealed class REQ_QUIC_RFC9000_S9P3P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationFailureKeepsUsingTheLastValidatedPeerAddress()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity lastValidatedPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity failedPath = new("203.0.113.21", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                failedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                failedPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(lastValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(lastValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsAbandoned);
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.Null(candidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
