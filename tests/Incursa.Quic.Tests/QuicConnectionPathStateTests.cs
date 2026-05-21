namespace Incursa.Quic.Tests;

public sealed class QuicConnectionPathStateTests
{
    [Fact]
    public void AppendRecentlyValidatedPath_BoundsCacheAndEvictsOldestEntry()
    {
        QuicConnectionPathState state = new(maximumRecentlyValidatedPaths: 1);
        QuicConnectionPathIdentity firstPath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity secondPath = new("203.0.113.11", RemotePort: 443);

        state.AppendRecentlyValidatedPath(
            firstPath,
            nowTicks: 10,
            savedRecoverySnapshot: null,
            amplificationState: default,
            maximumDatagramSizeState: QuicConnectionPathMaximumDatagramSizeState.CreateInitial());

        Assert.Single(state.RecentlyValidatedPaths);
        Assert.True(state.RecentlyValidatedPaths.TryGetValue(firstPath, out QuicConnectionValidatedPathRecord firstValidatedPath));
        Assert.True(firstValidatedPath.AmplificationState.IsAddressValidated);
        Assert.Equal(10L, firstValidatedPath.LastActivityTicks);

        state.AppendRecentlyValidatedPath(
            secondPath,
            nowTicks: 20,
            savedRecoverySnapshot: null,
            amplificationState: default,
            maximumDatagramSizeState: QuicConnectionPathMaximumDatagramSizeState.CreateInitial());

        Assert.Single(state.RecentlyValidatedPaths);
        Assert.DoesNotContain(firstPath, state.RecentlyValidatedPaths.Keys);
        Assert.True(state.RecentlyValidatedPaths.TryGetValue(secondPath, out QuicConnectionValidatedPathRecord secondValidatedPath));
        Assert.True(secondValidatedPath.AmplificationState.IsAddressValidated);
        Assert.Equal(20L, secondValidatedPath.LastActivityTicks);
    }

    [Fact]
    public void HasValidatedPath_ReturnsTrueForActiveCandidateAndRecentlyValidatedEntries()
    {
        QuicConnectionPathState state = new(maximumRecentlyValidatedPaths: 2);
        QuicConnectionPathIdentity activePath = new("203.0.113.20", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.21", RemotePort: 443);
        QuicConnectionPathIdentity validatedPath = new("203.0.113.22", RemotePort: 443);

        Assert.False(state.HasValidatedPath);

        state.ActivePath = new QuicConnectionActivePathRecord(
            activePath,
            ActivatedAtTicks: 1,
            LastActivityTicks: 1,
            IsValidated: true,
            RecoverySnapshot: null);

        Assert.True(state.HasValidatedPath);

        state.ActivePath = null;
        state.CandidatePaths[candidatePath] = new QuicConnectionCandidatePathRecord(
            candidatePath,
            DiscoveredAtTicks: 2,
            LastActivityTicks: 2,
            Validation: new QuicConnectionPathValidationState(
                Generation: 0,
                IsValidated: true,
                IsAbandoned: false,
                ChallengeSendCount: 0,
                ChallengeSentAtTicks: null,
                ValidationDeadlineTicks: null,
                ChallengePayload: ReadOnlyMemory<byte>.Empty,
                PreviousChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: null);

        Assert.True(state.HasValidatedPath);

        state.CandidatePaths.Clear();
        state.RecentlyValidatedPaths[validatedPath] = new QuicConnectionValidatedPathRecord(
            validatedPath,
            ValidatedAtTicks: 3,
            SavedRecoverySnapshot: null)
        {
            LastActivityTicks = 3,
        };

        Assert.True(state.HasValidatedPath);
    }

    [Fact]
    public void TryGetCandidatePathAndTryGetRecentlyValidatedPath_ReturnStoredEntries()
    {
        QuicConnectionPathState state = new(maximumRecentlyValidatedPaths: 1);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.30", RemotePort: 443);
        QuicConnectionPathIdentity validatedPath = new("203.0.113.31", RemotePort: 443);

        state.CandidatePaths[candidatePath] = new QuicConnectionCandidatePathRecord(
            candidatePath,
            DiscoveredAtTicks: 5,
            LastActivityTicks: 5,
            Validation: new QuicConnectionPathValidationState(
                Generation: 0,
                IsValidated: false,
                IsAbandoned: false,
                ChallengeSendCount: 0,
                ChallengeSentAtTicks: null,
                ValidationDeadlineTicks: null,
                ChallengePayload: ReadOnlyMemory<byte>.Empty,
                PreviousChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: null);

        state.RecentlyValidatedPaths[validatedPath] = new QuicConnectionValidatedPathRecord(
            validatedPath,
            ValidatedAtTicks: 6,
            SavedRecoverySnapshot: null);

        Assert.True(state.TryGetCandidatePath(candidatePath, out QuicConnectionCandidatePathRecord storedCandidate));
        Assert.Equal(candidatePath, storedCandidate.Identity);

        Assert.True(state.TryGetRecentlyValidatedPath(validatedPath, out QuicConnectionValidatedPathRecord storedValidatedPath));
        Assert.Equal(validatedPath, storedValidatedPath.Identity);

        Assert.False(state.TryGetCandidatePath(validatedPath, out _));
        Assert.False(state.TryGetRecentlyValidatedPath(candidatePath, out _));
    }
}
