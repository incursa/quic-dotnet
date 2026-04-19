namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P3-0004")]
public sealed class REQ_QUIC_RFC9000_S9P3P3_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0004")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ASecondMigratedAddressIsClassifiedAsNoiseWhenTheCandidateBudgetIsExhausted()
    {
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionPathIdentity activePath = new("203.0.113.90", RemotePort: 443);
        QuicConnectionPathIdentity firstMigratedPath = new("203.0.113.91", RemotePort: 443);
        QuicConnectionPathIdentity secondMigratedPath = new("203.0.113.92", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePathAndCandidateBudget(activePath, diagnosticsSink, maximumCandidatePaths: 1);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                firstMigratedPath,
                datagram),
            nowTicks: 3).StateChanged);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 4,
                secondMigratedPath,
                datagram),
            nowTicks: 4);

        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.CandidatePathBudgetExhausted
            && diagnosticEvent.PathIdentity == secondMigratedPath
            && diagnosticEvent.PathClassification == QuicConnectionPathClassification.NoiseOrAttack);
        Assert.True(runtime.CandidatePaths.ContainsKey(firstMigratedPath));
        Assert.False(runtime.CandidatePaths.ContainsKey(secondMigratedPath));
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == secondMigratedPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ASecondMigratedAddressContinuesValidationWhenCandidateCapacityRemains()
    {
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionPathIdentity activePath = new("203.0.113.93", RemotePort: 443);
        QuicConnectionPathIdentity firstMigratedPath = new("203.0.113.94", RemotePort: 443);
        QuicConnectionPathIdentity secondMigratedPath = new("203.0.113.95", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePathAndCandidateBudget(activePath, diagnosticsSink, maximumCandidatePaths: 2);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                firstMigratedPath,
                datagram),
            nowTicks: 3).StateChanged);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 4,
                secondMigratedPath,
                datagram),
            nowTicks: 4);

        Assert.DoesNotContain(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.CandidatePathBudgetExhausted
            && diagnosticEvent.PathIdentity == secondMigratedPath);
        Assert.True(runtime.CandidatePaths.TryGetValue(firstMigratedPath, out QuicConnectionCandidatePathRecord firstCandidatePath));
        Assert.True(runtime.CandidatePaths.TryGetValue(secondMigratedPath, out QuicConnectionCandidatePathRecord secondCandidatePath));
        Assert.Equal(1UL, firstCandidatePath.Validation.ChallengeSendCount);
        Assert.Equal(1UL, secondCandidatePath.Validation.ChallengeSendCount);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == secondMigratedPath);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void AMigratedAddressIsClassifiedAsNoiseWhenTheCandidateBudgetIsZero()
    {
        QuicRecordingDiagnosticsSink diagnosticsSink = new();
        QuicConnectionPathIdentity activePath = new("203.0.113.96", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.97", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];
        QuicConnectionRuntime runtime = CreateRuntimeWithActivePathAndCandidateBudget(activePath, diagnosticsSink, maximumCandidatePaths: 0);
        string? initialLastValidatedRemoteAddress = runtime.LastValidatedRemoteAddress;

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 4,
                migratedPath,
                datagram),
            nowTicks: 4);

        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.AddressChangeClassified
            && diagnosticEvent.PathIdentity == migratedPath
            && diagnosticEvent.PathClassification == QuicConnectionPathClassification.MigrationCandidate);
        Assert.Contains(diagnosticsSink.Events, diagnosticEvent =>
            diagnosticEvent.Kind == QuicDiagnosticKind.CandidatePathBudgetExhausted
            && diagnosticEvent.PathIdentity == migratedPath
            && diagnosticEvent.PathClassification == QuicConnectionPathClassification.NoiseOrAttack);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(initialLastValidatedRemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Empty(runtime.CandidatePaths);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == migratedPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ARecentlyValidatedAddressIsReusedEvenWhenAnotherCandidateOccupiesTheBudget()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            maximumCandidatePaths: 1);
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity migratedPath = new("203.0.113.99", RemotePort: 443);
        QuicConnectionPathIdentity budgetOccupyingPath = new("203.0.113.100", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 3,
                migratedPath,
                datagram),
            nowTicks: 3).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 4);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(activePath));

        QuicConnectionTransitionResult budgetOccupyingResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 5,
                budgetOccupyingPath,
                datagram),
            nowTicks: 5);

        Assert.True(budgetOccupyingResult.StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(budgetOccupyingPath, out QuicConnectionCandidatePathRecord budgetOccupyingCandidatePath));
        Assert.False(budgetOccupyingCandidatePath.Validation.IsValidated);
        Assert.False(budgetOccupyingCandidatePath.Validation.IsAbandoned);

        QuicConnectionTransitionResult reuseResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 6,
                activePath,
                datagram),
            nowTicks: 6);

        Assert.True(reuseResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(activePath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(activePath));
        Assert.True(runtime.CandidatePaths.TryGetValue(budgetOccupyingPath, out budgetOccupyingCandidatePath));
        Assert.DoesNotContain(runtime.CandidatePaths, entry => entry.Key.Equals(activePath));
        Assert.Contains(reuseResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == activePath
            && !promote.RestoreSavedState);
    }

    private static QuicConnectionRuntime CreateRuntimeWithActivePathAndCandidateBudget(
        QuicConnectionPathIdentity activePath,
        QuicRecordingDiagnosticsSink diagnosticsSink,
        int maximumCandidatePaths)
    {
        QuicConnectionRuntime runtime = new(
            QuicConnectionStreamStateTestHelpers.CreateState(),
            new FakeMonotonicClock(0),
            maximumCandidatePaths: maximumCandidatePaths,
            diagnosticsSink: diagnosticsSink);

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 1),
            nowTicks: 1).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 2,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 2).StateChanged);

        return runtime;
    }

    private sealed class FakeMonotonicClock : IMonotonicClock
    {
        public FakeMonotonicClock(long ticks)
        {
            Ticks = ticks;
        }

        public long Ticks { get; }

        public double Seconds => Ticks / (double)TimeSpan.TicksPerSecond;
    }
}
