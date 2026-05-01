namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0072")]
public sealed class REQ_QUIC_CRT_0072
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CandidateValidationFailureKeepsTheLastValidatedActivePath()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity lastValidatedPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity failedPath = new("203.0.113.173", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, failedPath, datagram),
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
        Assert.Equal(lastValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(lastValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsAbandoned);
        Assert.Null(candidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
