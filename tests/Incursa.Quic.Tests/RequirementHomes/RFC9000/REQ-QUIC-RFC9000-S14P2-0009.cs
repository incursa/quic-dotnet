namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S14P2-0009">QUIC implementations that implement any kind of PMTU discovery SHOULD maintain a maximum datagram size for each combination of local and remote IP addresses.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S14P2-0009")]
public sealed class REQ_QUIC_RFC9000_S14P2_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void CreateInitialMaximumDatagramSizeState_UsesTheRfcMinimumAndProjectsToTheActivePath()
    {
        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState = QuicConnectionPathMaximumDatagramSizeState.CreateInitial();

        Assert.Equal((ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize, maximumDatagramSizeState.MaximumDatagramSizeBytes);

        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new QuicConnectionPathIdentity("203.0.113.9", RemotePort: 443));

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes,
            runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
        Assert.Equal(
            (ulong)QuicVersionNegotiation.Version1MinimumDatagramPayloadSize,
            runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void Constructor_RejectsZeroMaximumDatagramSizes()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new QuicConnectionPathMaximumDatagramSizeState(0));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PathRecordsCarryMaximumDatagramSizeStateAcrossCopies()
    {
        QuicConnectionPathIdentity identity = new(
            RemoteAddress: "198.51.100.44",
            LocalAddress: "203.0.113.44",
            RemotePort: 443,
            LocalPort: 55555);

        QuicConnectionPathRecoverySnapshot recovery = new(
            SmoothedRttMicros: 1_000,
            RttVarMicros: 250,
            CongestionWindowBytes: 12_000,
            BytesInFlightBytes: 4_096,
            EcnValidated: true);

        QuicConnectionPathMaximumDatagramSizeState maximumDatagramSizeState = new(1_350);

        QuicConnectionActivePathRecord activePath = new(
            identity,
            ActivatedAtTicks: 10,
            LastActivityTicks: 11,
            IsValidated: true,
            RecoverySnapshot: recovery)
        {
            AmplificationState = new QuicConnectionPathAmplificationState(
                ReceivedPayloadBytes: 64,
                SentPayloadBytes: 16,
                IsAddressValidated: true),
            MaximumDatagramSizeState = maximumDatagramSizeState,
        };

        QuicConnectionCandidatePathRecord candidatePath = new(
            identity,
            DiscoveredAtTicks: 12,
            LastActivityTicks: 13,
            Validation: new QuicConnectionPathValidationState(
                Generation: 7,
                IsValidated: true,
                IsAbandoned: false,
                ChallengeSendCount: 2,
                ChallengeSentAtTicks: 100,
                ValidationDeadlineTicks: null,
                ChallengePayload: ReadOnlyMemory<byte>.Empty),
            SavedRecoverySnapshot: recovery)
        {
            AmplificationState = new QuicConnectionPathAmplificationState(
                ReceivedPayloadBytes: 48,
                SentPayloadBytes: 8,
                IsAddressValidated: false),
            MaximumDatagramSizeState = activePath.MaximumDatagramSizeState,
        };

        QuicConnectionValidatedPathRecord validatedPath = new(
            identity,
            ValidatedAtTicks: 14,
            SavedRecoverySnapshot: recovery)
        {
            LastActivityTicks = 15,
            AmplificationState = new QuicConnectionPathAmplificationState(
                ReceivedPayloadBytes: 96,
                SentPayloadBytes: 24,
                IsAddressValidated: true),
            MaximumDatagramSizeState = candidatePath.MaximumDatagramSizeState,
        };

        QuicConnectionCandidatePathRecord copiedCandidatePath = candidatePath with
        {
            LastActivityTicks = 16,
        };

        Assert.Equal(1_350UL, activePath.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(activePath.MaximumDatagramSizeState, candidatePath.MaximumDatagramSizeState);
        Assert.Equal(candidatePath.MaximumDatagramSizeState, validatedPath.MaximumDatagramSizeState);
        Assert.Equal(candidatePath.MaximumDatagramSizeState, copiedCandidatePath.MaximumDatagramSizeState);
    }
}
