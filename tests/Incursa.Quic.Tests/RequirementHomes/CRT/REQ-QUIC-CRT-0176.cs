// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0176")]
public sealed class REQ_QUIC_CRT_0176
{
    [Theory]
    [InlineData((int)QuicApplicationSendTurnSignalMask.QueuedApplicationWrites)]
    [InlineData((int)QuicApplicationSendTurnSignalMask.Congestion)]
    [InlineData((int)QuicApplicationSendTurnSignalMask.Lifecycle)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void MissingRequiredSignalRecommendsConservativeFallback(int missingSignal)
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                MissingSignalMask = (QuicApplicationSendTurnSignalMask)missingSignal,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.MissingSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StaleRequiredSignalRecommendsConservativeFallback()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                StaleSignalMask = QuicApplicationSendTurnSignalMask.ActorServiceTimeEwma,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.StaleSignal);
    }

    [Theory]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.ArithmeticSaturated,
        (int)QuicApplicationSendTurnShadowReason.ArithmeticSaturated)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.Contradictory,
        (int)QuicApplicationSendTurnShadowReason.ContradictorySignals)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.OutOfDomain,
        (int)QuicApplicationSendTurnShadowReason.OutOfDomain)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.RecoveryUnstable,
        (int)QuicApplicationSendTurnShadowReason.RecoveryGuard)]
    [InlineData(
        (int)QuicApplicationSendTurnObservationCondition.ResourceConstrained,
        (int)QuicApplicationSendTurnShadowReason.ResourceGuard)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BoundedGuardFlagsHaveDeterministicReasons(int flagsValue, int reasonValue)
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                Conditions = (QuicApplicationSendTurnObservationCondition)flagsValue,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, (QuicApplicationSendTurnShadowReason)reasonValue);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void FallbackReasonPrecedenceIsStable()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                MissingSignalMask = QuicApplicationSendTurnSignalMask.Congestion,
                StaleSignalMask = QuicApplicationSendTurnSignalMask.Lifecycle,
                Conditions = QuicApplicationSendTurnObservationCondition.ArithmeticSaturated
                    | QuicApplicationSendTurnObservationCondition.RecoveryUnstable,
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.MissingSignal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void VersionMismatchRecommendsConservativeFallback()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation observation =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                PolicyRuleVersion = "unreviewed-rule",
            };

        Assert.True(controller.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot snapshot));

        AssertFallback(snapshot, QuicApplicationSendTurnShadowReason.RuleVersionMismatch);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void DuplicateAndOutOfOrderTurnsAreRejected()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation first =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2);
        Assert.True(controller.TryEvaluate(in first, out QuicApplicationSendTurnPolicySnapshot firstSnapshot));

        Assert.False(controller.TryEvaluate(in first, out _));
        QuicApplicationSendTurnObservation earlier =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1);
        Assert.False(controller.TryEvaluate(in earlier, out _));

        QuicApplicationSendTurnObservation next =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 3);
        Assert.True(controller.TryEvaluate(in next, out QuicApplicationSendTurnPolicySnapshot nextSnapshot));
        Assert.Equal(firstSnapshot.SnapshotSequence + 1, nextSnapshot.SnapshotSequence);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void IdenticalOrderedObservationsReplayIdentically()
    {
        QuicApplicationSendTurnShadowController first = default;
        QuicApplicationSendTurnShadowController second = default;
        QuicApplicationSendTurnObservation[] observations =
        [
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1),
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2) with
            {
                Conditions = QuicApplicationSendTurnObservationCondition.ResourceConstrained,
            },
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 3),
        ];

        foreach (QuicApplicationSendTurnObservation observation in observations)
        {
            Assert.True(first.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot firstSnapshot));
            Assert.True(second.TryEvaluate(in observation, out QuicApplicationSendTurnPolicySnapshot secondSnapshot));
            Assert.Equal(firstSnapshot, secondSnapshot);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TerminalStateCannotReturnToLegacyState()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation terminal =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1) with
            {
                LifecycleFlags = QuicAdaptiveRuntimeLifecycle.Closing
                    | QuicAdaptiveRuntimeLifecycle.Terminal,
            };
        Assert.True(controller.TryEvaluate(in terminal, out QuicApplicationSendTurnPolicySnapshot terminalSnapshot));
        Assert.Equal(QuicApplicationSendTurnShadowState.Terminal, terminalSnapshot.State);

        QuicApplicationSendTurnObservation active =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 2);
        Assert.True(controller.TryEvaluate(in active, out QuicApplicationSendTurnPolicySnapshot laterSnapshot));
        Assert.Equal(QuicApplicationSendTurnShadowState.Terminal, laterSnapshot.State);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, laterSnapshot.RecommendedPolicy);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RuntimeInputContractExcludesWorkloadAndIdentityLabels()
    {
        string[] forbiddenNames =
        [
            "Scenario",
            "Workload",
            "PayloadConstant",
            "RequestedConcurrency",
            "PeerIdentity",
            "Url",
            "ApplicationIdentity",
        ];
        string[] propertyNames = typeof(QuicApplicationSendTurnObservation)
            .GetProperties()
            .Select(static property => property.Name)
            .ToArray();

        foreach (string forbiddenName in forbiddenNames)
        {
            Assert.DoesNotContain(forbiddenName, propertyNames, StringComparer.OrdinalIgnoreCase);
        }
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RawHostKeepsShadowEvidenceSeparateFromForcedConstructionProvenance()
    {
        string source = File.ReadAllText(AdaptiveRuntimePolicyScriptTestSupport.FindRepositoryFile(
            "eng/protocol-lab/servers/IncursaRawQuicServer/Program.cs"));

        Assert.Contains(
            "adaptive-runtime-application-send-turn-provenance-v1",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "adaptive-runtime-application-send-turn-raw-v1",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "QUIC_APPLICATION_SEND_TURN_POLICY_JSON=",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "QUIC_APPLICATION_SEND_TURN_EVIDENCE_JSON=",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "IQuicApplicationSendTurnEvidenceSink",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "evidence.HasRecommendation ? evidence.Snapshot : null",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "Only one adaptive-runtime policy axis can be forced or observed",
            source,
            StringComparison.Ordinal);
        Assert.Contains(
            "? QuicReceiveCreditPolicyMode.LegacyCurrent",
            source,
            StringComparison.Ordinal);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void QueueObservationStopsAtTheReviewedBoundAndMarksPartialEvidence()
    {
        QuicApplicationSendQueue queue = new();
        for (int index = 0; index < 65; index++)
        {
            queue.EnqueueRawStreamData(
                streamId: (ulong)index,
                priority: 0,
                streamData: new byte[8],
                streamDataLength: 4,
                streamOffset: 0,
                isFinal: false,
                firstEnqueuedAtMicros: (ulong)(100 + index));
        }

        QuicApplicationSendTurnQueueSnapshot snapshot = queue.CaptureBoundedTurnSnapshot(
            nowMicros: 1_000,
            maximumObservedWrites: 64,
            maximumObservedDistinctStreams: 12);

        Assert.False(snapshot.Complete);
        Assert.Equal(65U, snapshot.QueuedApplicationWrites);
        Assert.Equal(65U, snapshot.RetainedSendBuffers);
        Assert.Equal(256UL, snapshot.OutboundBacklogBytes);
        Assert.Equal(512UL, snapshot.RetainedSendBytes);
        Assert.Equal(12, snapshot.DistinctQueuedStreams);
        Assert.Equal(900UL, snapshot.OldestQueuedSendAgeMicros);
    }

    [Theory]
    [InlineData((int)QuicApplicationSendTurnObservationMode.Disabled, true)]
    [InlineData((int)QuicApplicationSendTurnObservationMode.Shadow, false)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void EvidenceSinkConfigurationMustMatchTheObservationMode(
        int modeValue,
        bool includeSink)
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ApplicationSendTurnObservationMode =
                (QuicApplicationSendTurnObservationMode)modeValue,
            ApplicationSendTurnEvidenceSink = includeSink
                ? new RecordingEvidenceSink()
                : null,
        };

        Assert.Throws<InvalidOperationException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void UndefinedObservationModeIsRejectedWithoutPartialConfiguration()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicClientConnectionOptions options = new()
        {
            ApplicationSendTurnObservationMode = (QuicApplicationSendTurnObservationMode)byte.MaxValue,
            ApplicationSendTurnEvidenceSink = new RecordingEvidenceSink(),
        };

        Assert.Throws<ArgumentOutOfRangeException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(options));
        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ListenerOptionCopyPreservesAxisSpecificModeAndSink()
    {
        RecordingEvidenceSink sink = new();
        QuicServerConnectionOptions selectedOptions = new();
        QuicServerConnectionOptions returnedOptions = new()
        {
            ApplicationSendTurnObservationMode =
                QuicApplicationSendTurnObservationMode.ObserveOnly,
            ApplicationSendTurnEvidenceSink = sink,
        };

        QuicListenerHost.ApplyReturnedOptions(selectedOptions, returnedOptions);

        Assert.Equal(
            QuicApplicationSendTurnObservationMode.ObserveOnly,
            selectedOptions.ApplicationSendTurnObservationMode);
        Assert.Same(sink, selectedOptions.ApplicationSendTurnEvidenceSink);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackRestoresTheDisabledNullPlannerBaseline()
    {
        using QuicConnectionRuntime runtime = new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(new QuicClientConnectionOptions
        {
            ForcedReceiveCreditPolicyMode = QuicReceiveCreditPolicyMode.LegacyCurrent,
            ForcedApplicationSendTurnPolicyMode = QuicApplicationSendTurnPolicyMode.LegacyCurrent,
        });

        Assert.Equal(
            QuicApplicationSendTurnObservationMode.Disabled,
            runtime.ApplicationSendTurnObservationMode);
        Assert.Equal(
            QuicApplicationSendTurnPolicyMode.LegacyCurrent,
            runtime.ApplicationSendTurnPolicyMode);
        Assert.Null(runtime.ApplicationSendTurnPlanner);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void SteadyStateEvaluationDoesNotAllocate()
    {
        QuicApplicationSendTurnShadowController controller = default;
        QuicApplicationSendTurnObservation warmup =
            QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence: 1);
        Assert.True(controller.TryEvaluate(in warmup, out _));

        bool allEvaluated = true;
        long allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
        for (ulong turnSequence = 2; turnSequence < 1026; turnSequence++)
        {
            QuicApplicationSendTurnObservation observation =
                QuicApplicationSendTurnShadowTestSupport.CreateObservation(turnSequence);
            allEvaluated &= controller.TryEvaluate(in observation, out _);
        }

        long allocatedAfter = GC.GetAllocatedBytesForCurrentThread();
        Assert.True(allEvaluated);
        Assert.Equal(allocatedBefore, allocatedAfter);
    }

    private static void AssertFallback(
        QuicApplicationSendTurnPolicySnapshot snapshot,
        QuicApplicationSendTurnShadowReason expectedReason)
    {
        Assert.Equal(QuicApplicationSendTurnShadowState.Fallback, snapshot.State);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.LegacyCurrent, snapshot.AppliedPolicy);
        Assert.Equal(QuicApplicationSendTurnPolicyMode.Conservative, snapshot.RecommendedPolicy);
        Assert.Equal(expectedReason, snapshot.Reason);
    }

    private sealed class RecordingEvidenceSink : IQuicApplicationSendTurnEvidenceSink
    {
        public bool TryPublish(in QuicApplicationSendTurnEvidence evidence) => true;
    }
}

internal static class QuicApplicationSendTurnShadowTestSupport
{
    internal static QuicApplicationSendTurnObservation CreateObservation(ulong turnSequence)
        => new(
            turnSequence,
            CapturedAtTicks: checked((long)turnSequence),
            QuicApplicationSendTurnObservation.CurrentObservationContractVersion,
            QuicApplicationSendTurnObservation.CurrentPolicyRuleVersion,
            MissingSignalMask: QuicApplicationSendTurnSignalMask.None,
            StaleSignalMask: QuicApplicationSendTurnSignalMask.None,
            Conditions: QuicApplicationSendTurnObservationCondition.None,
            LifecycleFlags: QuicAdaptiveRuntimeLifecycle.Active,
            QueuedApplicationWrites: 4,
            OutboundBacklogBytes: 4_096,
            DistinctQueuedStreams: 4,
            OldestQueuedSendAgeMicros: 250,
            QueueDelayEwmaMicros: 100,
            ActorServiceTimeEwmaMicros: 50,
            BurstLimitHits: 0,
            BytesInFlight: 1_024,
            CongestionWindowBytes: 12_000,
            RetainedSendBuffers: 4,
            RetainedSendBytes: 4_096);
}
