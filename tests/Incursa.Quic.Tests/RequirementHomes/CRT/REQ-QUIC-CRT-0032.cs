namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0032")]
public sealed class REQ_QUIC_CRT_0032
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RuntimeExposesTheConnectionOwnedStateInventory()
    {
        QuicConnectionStreamState bookkeeping = QuicConnectionStreamStateTestHelpers.CreateState();
        QuicConnectionRuntime runtime = new(bookkeeping);

        Assert.Equal(QuicConnectionPhase.Establishing, runtime.Phase);
        Assert.False(runtime.HandshakeConfirmed);
        Assert.Equal(QuicConnectionTransportState.None, runtime.TransportFlags);
        Assert.Null(runtime.ActivePath);
        Assert.Empty(runtime.CandidatePaths);
        Assert.Empty(runtime.RecentlyValidatedPaths);
        Assert.False(runtime.TimerState.HasAnyDeadline);
        Assert.Equal(0UL, runtime.TimerState.Generation);
        Assert.Equal(0UL, runtime.TimerState.NextSequence);
        Assert.Null(runtime.TerminalState);
        Assert.Null(runtime.LastValidatedRemoteAddress);
        Assert.Same(bookkeeping, runtime.StreamRegistry.Bookkeeping);
        Assert.Empty(runtime.StreamRegistry.Streams);
        Assert.Equal(0, runtime.StreamRegistry.Count);
        Assert.Equal(8, runtime.MaximumCandidatePaths);
        Assert.Equal(8, runtime.MaximumRecentlyValidatedPaths);
        Assert.Equal(0L, runtime.LastTransitionTicks);
        Assert.Equal(0UL, runtime.TransitionSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PathAndTimerModelRecordsCarryTheirExpectedFields()
    {
        QuicConnectionPathIdentity identity = new(
            RemoteAddress: "203.0.113.9",
            LocalAddress: "198.51.100.3",
            RemotePort: 443,
            LocalPort: 55555);

        QuicConnectionPathRecoverySnapshot recovery = new(
            SmoothedRttMicros: 1000,
            RttVarMicros: 250,
            CongestionWindowBytes: 12_000,
            BytesInFlightBytes: 4_096,
            EcnValidated: true);

        QuicConnectionPathValidationState validation = new(
            Generation: 7,
            IsValidated: false,
            IsAbandoned: false,
            ChallengeSendCount: 2,
            ChallengeSentAtTicks: 100,
            ValidationDeadlineTicks: 200,
            ChallengePayload: ReadOnlyMemory<byte>.Empty);

        QuicConnectionActivePathRecord activePath = new(
            Identity: identity,
            ActivatedAtTicks: 10,
            LastActivityTicks: 11,
            IsValidated: true,
            RecoverySnapshot: recovery);

        QuicConnectionCandidatePathRecord candidatePath = new(
            Identity: identity,
            DiscoveredAtTicks: 12,
            LastActivityTicks: 13,
            Validation: validation,
            SavedRecoverySnapshot: recovery);

        QuicConnectionValidatedPathRecord validatedPath = new(
            Identity: identity,
            ValidatedAtTicks: 14,
            SavedRecoverySnapshot: recovery);

        QuicConnectionTimerDeadlineState deadlineState = new(
            IdleTimeoutDueTicks: 1_000,
            CloseLifetimeDueTicks: 2_000,
            DrainLifetimeDueTicks: null,
            Generation: 9,
            NextSequence: 3);

        Assert.Equal("203.0.113.9", activePath.Identity.RemoteAddress);
        Assert.Equal("198.51.100.3", activePath.Identity.LocalAddress);
        Assert.Equal(10, activePath.ActivatedAtTicks);
        Assert.Equal(11, activePath.LastActivityTicks);
        Assert.True(activePath.IsValidated);
        Assert.True(activePath.RecoverySnapshot.HasValue);
        Assert.Equal(recovery, activePath.RecoverySnapshot.Value);

        Assert.Equal(identity, candidatePath.Identity);
        Assert.Equal(12, candidatePath.DiscoveredAtTicks);
        Assert.Equal(13, candidatePath.LastActivityTicks);
        Assert.Equal(7UL, candidatePath.Validation.Generation);
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(2UL, candidatePath.Validation.ChallengeSendCount);
        Assert.Equal(100L, candidatePath.Validation.ChallengeSentAtTicks);
        Assert.Equal(200L, candidatePath.Validation.ValidationDeadlineTicks);
        Assert.True(candidatePath.Validation.ChallengePayload.IsEmpty);
        Assert.True(candidatePath.SavedRecoverySnapshot.HasValue);
        Assert.Equal(recovery, candidatePath.SavedRecoverySnapshot.Value);

        Assert.Equal(identity, validatedPath.Identity);
        Assert.Equal(14, validatedPath.ValidatedAtTicks);
        Assert.True(validatedPath.SavedRecoverySnapshot.HasValue);
        Assert.Equal(recovery, validatedPath.SavedRecoverySnapshot.Value);

        Assert.True(deadlineState.HasAnyDeadline);
        Assert.Equal(9UL, deadlineState.Generation);
        Assert.Equal(3UL, deadlineState.NextSequence);
        Assert.Equal(new QuicConnectionTimerPriority(1_000, 3), deadlineState.CreatePriority(1_000));
    }
}
