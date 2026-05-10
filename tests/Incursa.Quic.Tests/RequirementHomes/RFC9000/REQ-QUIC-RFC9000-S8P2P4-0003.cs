namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S8P2P4-0003")]
public sealed class REQ_QUIC_RFC9000_S8P2P4_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NoViablePathIsSignaledWhenTheLastCandidatePathFails()
    {
        (QuicConnectionRuntime runtime, _, QuicConnectionPathIdentity candidatePath) =
            QuicS8P2P4NoViablePathTestSupport.CreateRuntimeWithCandidatePath(
                activeAddress: "203.0.113.40",
                candidateAddress: "203.0.113.41",
                validateActivePath: false);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                candidatePath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicTransportErrorCode.NoViablePath, runtime.TerminalState.Value.Close.TransportErrorCode);
        Assert.Equal("The endpoint has no viable path to its peer.", runtime.TerminalState.Value.Close.ReasonPhrase);
        Assert.Contains(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NoViablePathIsNotSignaledWhenAnAlternateValidatedPathRemains()
    {
        (QuicConnectionRuntime runtime, QuicConnectionPathIdentity activePath, QuicConnectionPathIdentity candidatePath) =
            QuicS8P2P4NoViablePathTestSupport.CreateRuntimeWithCandidatePath(
                activeAddress: "203.0.113.40",
                candidateAddress: "203.0.113.41",
                validateActivePath: true);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                candidatePath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.HasValidatedPath);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.True(candidate.Validation.IsAbandoned);
        Assert.False(candidate.Validation.IsValidated);
        Assert.Null(candidate.Validation.ValidationDeadlineTicks);
        Assert.Null(runtime.TerminalState);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }
}
