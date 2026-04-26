namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0062")]
public sealed class REQ_QUIC_CRT_0062
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PathRecordsCarryValidationAmplificationRecoveryAndChallengeState()
    {
        QuicConnectionPathIdentity identity = new(
            RemoteAddress: "203.0.113.70",
            LocalAddress: "198.51.100.7",
            RemotePort: 443,
            LocalPort: 55555);

        QuicConnectionPathRecoverySnapshot recovery = new(
            SmoothedRttMicros: 1_000,
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
            ChallengePayload: new byte[QuicPathValidation.PathChallengeDataLength]);

        QuicConnectionActivePathRecord activePath = new(
            Identity: identity,
            ActivatedAtTicks: 10,
            LastActivityTicks: 11,
            IsValidated: true,
            RecoverySnapshot: recovery)
        {
            AmplificationState = new QuicConnectionPathAmplificationState(
                ReceivedPayloadBytes: 64,
                SentPayloadBytes: 16,
                IsAddressValidated: true),
            MaximumDatagramSizeState = new QuicConnectionPathMaximumDatagramSizeState(1_350),
        };

        QuicConnectionCandidatePathRecord candidatePath = new(
            Identity: identity,
            DiscoveredAtTicks: 12,
            LastActivityTicks: 13,
            Validation: validation,
            SavedRecoverySnapshot: recovery)
        {
            AmplificationState = new QuicConnectionPathAmplificationState(
                ReceivedPayloadBytes: 48,
                SentPayloadBytes: 8,
                IsAddressValidated: false),
            MaximumDatagramSizeState = new QuicConnectionPathMaximumDatagramSizeState(1_400),
        };

        QuicConnectionValidatedPathRecord validatedPath = new(
            Identity: identity,
            ValidatedAtTicks: 14,
            SavedRecoverySnapshot: recovery)
        {
            LastActivityTicks = 15,
            AmplificationState = new QuicConnectionPathAmplificationState(
                ReceivedPayloadBytes: 96,
                SentPayloadBytes: 24,
                IsAddressValidated: true),
            MaximumDatagramSizeState = new QuicConnectionPathMaximumDatagramSizeState(1_450),
        };

        Assert.Equal(identity, activePath.Identity);
        Assert.Equal(10, activePath.ActivatedAtTicks);
        Assert.Equal(11, activePath.LastActivityTicks);
        Assert.True(activePath.IsValidated);
        Assert.True(activePath.RecoverySnapshot.HasValue);
        Assert.Equal(recovery, activePath.RecoverySnapshot.Value);
        Assert.Equal(64UL, activePath.AmplificationState.ReceivedPayloadBytes);
        Assert.Equal(16UL, activePath.AmplificationState.SentPayloadBytes);
        Assert.True(activePath.AmplificationState.IsAddressValidated);
        Assert.Equal(1_350UL, activePath.MaximumDatagramSizeState.MaximumDatagramSizeBytes);

        Assert.Equal(identity, candidatePath.Identity);
        Assert.Equal(12, candidatePath.DiscoveredAtTicks);
        Assert.Equal(13, candidatePath.LastActivityTicks);
        Assert.Equal(7UL, candidatePath.Validation.Generation);
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(2UL, candidatePath.Validation.ChallengeSendCount);
        Assert.Equal(100L, candidatePath.Validation.ChallengeSentAtTicks);
        Assert.Equal(200L, candidatePath.Validation.ValidationDeadlineTicks);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.True(candidatePath.SavedRecoverySnapshot.HasValue);
        Assert.Equal(recovery, candidatePath.SavedRecoverySnapshot.Value);
        Assert.Equal(48UL, candidatePath.AmplificationState.ReceivedPayloadBytes);
        Assert.Equal(8UL, candidatePath.AmplificationState.SentPayloadBytes);
        Assert.False(candidatePath.AmplificationState.IsAddressValidated);
        Assert.Equal(1_400UL, candidatePath.MaximumDatagramSizeState.MaximumDatagramSizeBytes);

        Assert.Equal(identity, validatedPath.Identity);
        Assert.Equal(14, validatedPath.ValidatedAtTicks);
        Assert.Equal(15, validatedPath.LastActivityTicks);
        Assert.True(validatedPath.SavedRecoverySnapshot.HasValue);
        Assert.Equal(recovery, validatedPath.SavedRecoverySnapshot.Value);
        Assert.Equal(96UL, validatedPath.AmplificationState.ReceivedPayloadBytes);
        Assert.Equal(24UL, validatedPath.AmplificationState.SentPayloadBytes);
        Assert.True(validatedPath.AmplificationState.IsAddressValidated);
        Assert.Equal(1_450UL, validatedPath.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
    }
}
