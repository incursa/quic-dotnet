// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests.RequirementHomes.CRT;

[Requirement("REQ-QUIC-CRT-0194")]
public sealed class REQ_QUIC_CRT_0194
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForcedBoundedChoiceSelectsTheLessLoadedCandidate()
    {
        QuicConnectionShardPlacementDecision candidates =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Disabled,
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices,
                connectionHandleValue: 17,
                shardCount: 4,
                legacyShardActiveConnections: 7,
                alternateShardActiveConnections: 2,
                lifecycleGuard: false);

        Assert.NotEqual(
            candidates.LegacyShardIndex,
            candidates.AlternateShardIndex);
        Assert.Equal(
            candidates.AlternateShardIndex,
            candidates.AppliedShardIndex);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices,
            candidates.AppliedValue);
        Assert.Equal(
            QuicConnectionShardPlacementSelectionSource.Forced,
            candidates.SelectionSource);
        Assert.Equal(
            QuicConnectionShardPlacementReasonCode
                .LowerActiveCountApplied,
            candidates.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ForceLegacyRollbackUsesTheRetainedHandleModuloRule()
    {
        QuicConnectionShardPlacementDecision decision =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Disabled,
                QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
                connectionHandleValue: 17,
                shardCount: 4,
                legacyShardActiveConnections: 9,
                alternateShardActiveConnections: 0,
                lifecycleGuard: false);

        Assert.Equal(1, decision.LegacyShardIndex);
        Assert.Equal(1, decision.AppliedShardIndex);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            QuicConnectionShardPlacementReasonCode.LegacyModuloApplied,
            decision.ReasonCode);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ShadowRecommendsBoundedChoiceWhileApplyingLegacy()
    {
        QuicConnectionShardPlacementDecision decision =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Shadow,
                forcedValue: null,
                connectionHandleValue: 17,
                shardCount: 4,
                legacyShardActiveConnections: 5,
                alternateShardActiveConnections: 0,
                lifecycleGuard: false);

        Assert.True(decision.HasShadowRecommendation);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices,
            decision.ShadowRecommendation);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices,
            decision.SelectedValue);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            decision.LegacyShardIndex,
            decision.AppliedShardIndex);
    }

    [Theory]
    [InlineData(
        (byte)QuicConnectionShardPlacementValidity.MissingRequiredInput,
        (byte)QuicConnectionShardPlacementReasonCode.MissingInput)]
    [InlineData(
        (byte)QuicConnectionShardPlacementValidity.StaleRequiredInput,
        (byte)QuicConnectionShardPlacementReasonCode.StaleInput)]
    [InlineData(
        (byte)QuicConnectionShardPlacementValidity.ArithmeticSaturated,
        (byte)QuicConnectionShardPlacementReasonCode.ArithmeticSaturated)]
    [InlineData(
        (byte)QuicConnectionShardPlacementValidity.Contradictory,
        (byte)QuicConnectionShardPlacementReasonCode.Contradictory)]
    [InlineData(
        (byte)QuicConnectionShardPlacementValidity.OutOfDomain,
        (byte)QuicConnectionShardPlacementReasonCode.OutOfDomain)]
    [InlineData(
        (byte)QuicConnectionShardPlacementValidity.InvalidInput,
        (byte)QuicConnectionShardPlacementReasonCode.InvalidInput)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidInputsFallBackEvenWhenBoundedChoiceIsForced(
        byte validityValue,
        byte expectedReasonValue)
    {
        QuicConnectionShardPlacementDecision decision =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Shadow,
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices,
                connectionHandleValue: 17,
                shardCount: 4,
                legacyShardActiveConnections: 5,
                alternateShardActiveConnections: 0,
                lifecycleGuard: false,
                (QuicConnectionShardPlacementValidity)validityValue);

        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices,
            decision.SelectedValue);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            decision.AppliedValue);
        Assert.Equal(
            decision.LegacyShardIndex,
            decision.AppliedShardIndex);
        Assert.Equal(
            QuicConnectionShardPlacementSelectionSource.SafetyOverride,
            decision.SelectionSource);
        Assert.Equal(
            (QuicConnectionShardPlacementReasonCode)expectedReasonValue,
            decision.ReasonCode);
        Assert.True(decision.FallbackApplied);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void LifecycleAndSingleShardGuardsOverrideForcedChoice()
    {
        QuicConnectionShardPlacementDecision lifecycle =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Disabled,
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices,
                connectionHandleValue: 9,
                shardCount: 4,
                legacyShardActiveConnections: 5,
                alternateShardActiveConnections: 0,
                lifecycleGuard: true);
        QuicConnectionShardPlacementDecision singleShard =
            QuicConnectionShardPlacementPolicy.Evaluate(
                QuicConnectionShardPlacementObservationMode.Disabled,
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices,
                connectionHandleValue: 9,
                shardCount: 1,
                legacyShardActiveConnections: 0,
                alternateShardActiveConnections: 0,
                lifecycleGuard: false);

        Assert.Equal(
            QuicConnectionShardPlacementReasonCode.LifecycleGuard,
            lifecycle.ReasonCode);
        Assert.Equal(
            QuicConnectionShardPlacementReasonCode.SingleShardFallback,
            singleShard.ReasonCode);
        Assert.All(
            new[] { lifecycle, singleShard },
            static decision =>
            {
                Assert.True(decision.FallbackApplied);
                Assert.Equal(
                    QuicConnectionShardPlacementPolicyValue
                        .LegacyCurrent,
                    decision.AppliedValue);
            });
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HostLatchesBoundedChoiceForTheConnectionLifetime()
    {
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            placementObservationMode:
                QuicConnectionShardPlacementObservationMode.ObserveOnly,
            forcedPlacementValue:
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices);
        QuicConnectionRuntime first =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntime second =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = new(1);
        Assert.True(host.TryRegisterConnection(firstHandle, first));

        QuicConnectionHandle secondHandle = new(5);
        Assert.True(host.TryRegisterConnection(secondHandle, second));
        Assert.True(host.TryGetPlacementDecision(
            secondHandle,
            out QuicConnectionShardPlacementDecision placement));
        int latchedShard = host.GetShardIndex(secondHandle);

        Assert.Equal(placement.AppliedShardIndex, latchedShard);
        Assert.NotEqual(placement.LegacyShardIndex, latchedShard);
        Assert.Equal(1, host.GetActiveConnectionCount(latchedShard));
        Assert.True(host.TryUnregisterConnection(firstHandle));
        Assert.Equal(latchedShard, host.GetShardIndex(secondHandle));
        Assert.True(host.TryUnregisterConnection(secondHandle));
        Assert.Equal(0, host.GetActiveConnectionCount(latchedShard));

        await first.DisposeAsync();
        await second.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task FailedRegistrationRollsBackActiveCount()
    {
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            forcedPlacementValue:
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices);
        QuicConnectionHandle handle = new(1);
        QuicConnectionRuntime first =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntime duplicate =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        Assert.True(host.TryRegisterConnection(handle, first));
        int shard = host.GetShardIndex(handle);
        Assert.Equal(1, host.GetActiveConnectionCount(shard));

        Assert.False(host.TryRegisterConnection(handle, duplicate));
        Assert.Equal(1, host.GetActiveConnectionCount(shard));
        QuicConnectionHandle retryHandle = new(2);
        Assert.True(host.TryRegisterConnection(retryHandle, duplicate));
        Assert.True(host.TryUnregisterConnection(retryHandle));
        Assert.True(host.TryUnregisterConnection(handle));
        Assert.Equal(0, host.GetActiveConnectionCount(shard));

        await first.DisposeAsync();
        await duplicate.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task RuntimeOwnershipCannotBeSplitAcrossHosts()
    {
        using QuicConnectionRuntimeHost firstHost = new(4);
        using QuicConnectionRuntimeHost secondHost = new(
            shardCount: 4,
            forcedPlacementValue:
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices);
        QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle firstHandle = new(1);
        QuicConnectionHandle secondHandle = new(2);

        Assert.True(firstHost.TryRegisterConnection(firstHandle, runtime));
        Assert.False(secondHost.TryRegisterConnection(secondHandle, runtime));
        Assert.False(secondHost.TryGetPlacementDecision(
            secondHandle,
            out _));
        Assert.All(
            Enumerable.Range(0, secondHost.ShardCount),
            shard => Assert.Equal(
                0,
                secondHost.GetActiveConnectionCount(shard)));

        Assert.True(firstHost.TryUnregisterConnection(firstHandle));
        await runtime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task DisposedRuntimeAndDisposedHostRejectPlacement()
    {
        QuicConnectionRuntime disposedRuntime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        await disposedRuntime.DisposeAsync();
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            forcedPlacementValue:
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices);

        Assert.False(host.TryRegisterConnection(
            new QuicConnectionHandle(1),
            disposedRuntime));
        Assert.All(
            Enumerable.Range(0, host.ShardCount),
            shard => Assert.Equal(
                0,
                host.GetActiveConnectionCount(shard)));

        QuicConnectionRuntime liveRuntime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionRuntimeHost disposedHost = new(4);
        disposedHost.Dispose();
        Assert.False(disposedHost.TryRegisterConnection(
            new QuicConnectionHandle(2),
            liveRuntime));
        await liveRuntime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task StatefulRegisterUnregisterSequencePreservesCounts()
    {
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            forcedPlacementValue:
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices);
        List<(QuicConnectionHandle Handle, QuicConnectionRuntime Runtime)>
            registrations = [];
        for (ulong value = 1; value <= 64; value++)
        {
            QuicConnectionRuntime runtime =
                new(QuicConnectionStreamStateTestHelpers.CreateState());
            QuicConnectionHandle handle = new(value);
            Assert.True(host.TryRegisterConnection(handle, runtime));
            registrations.Add((handle, runtime));
        }

        Assert.Equal(
            64,
            Enumerable.Range(0, host.ShardCount)
                .Sum(host.GetActiveConnectionCount));
        foreach ((QuicConnectionHandle handle, _) in
            registrations.Where(static item =>
                (item.Handle.Value & 1UL) == 0))
        {
            Assert.True(host.TryUnregisterConnection(handle));
        }

        Assert.Equal(
            32,
            Enumerable.Range(0, host.ShardCount)
                .Sum(host.GetActiveConnectionCount));
        foreach ((QuicConnectionHandle handle, QuicConnectionRuntime runtime)
            in registrations)
        {
            if ((handle.Value & 1UL) != 0)
            {
                Assert.True(host.TryUnregisterConnection(handle));
            }

            await runtime.DisposeAsync();
        }

        Assert.All(
            Enumerable.Range(0, host.ShardCount),
            shard => Assert.Equal(
                0,
                host.GetActiveConnectionCount(shard)));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task LateEvidenceSinkReceivesTheImmutablePlacement()
    {
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            placementObservationMode:
                QuicConnectionShardPlacementObservationMode.Shadow);
        QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        QuicConnectionHandle handle = new(17);
        Assert.True(host.TryRegisterConnection(handle, runtime));
        RecordingPlacementSink sink = new();

        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ConnectionShardPlacementEvidenceSink = sink,
            });

        QuicConnectionShardPlacementDecision published =
            Assert.Single(sink.Decisions);
        Assert.Equal(handle.Value, published.ConnectionHandleValue);
        Assert.Equal(host.GetShardIndex(handle), published.AppliedShardIndex);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue.LegacyCurrent,
            published.AppliedValue);
        Assert.Equal(
            QuicConnectionShardPlacementPolicyValue
                .BoundedPowerOfTwoChoices,
            published.ShadowRecommendation);

        Assert.True(host.TryUnregisterConnection(handle));
        await runtime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task InvalidConfigurationDoesNotCaptureThePlacementSink()
    {
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            placementObservationMode:
                QuicConnectionShardPlacementObservationMode.ObserveOnly);
        QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        RecordingPlacementSink sink = new();

        Assert.Throws<ArgumentOutOfRangeException>(
            () => runtime.ConfigureAdaptiveRuntimePolicy(
                new QuicClientConnectionOptions
                {
                    ApplicationSendTurnObservationMode =
                        (QuicApplicationSendTurnObservationMode)byte.MaxValue,
                    ConnectionShardPlacementEvidenceSink = sink,
                }));

        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ConnectionShardPlacementEvidenceSink = sink,
            });
        QuicConnectionHandle handle = new(17);
        Assert.True(host.TryRegisterConnection(handle, runtime));
        Assert.Single(sink.Decisions);

        Assert.True(host.TryUnregisterConnection(handle));
        await runtime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ThrowingEvidenceSinkCannotChangeTheLatchedRoute()
    {
        using QuicConnectionRuntimeHost host = new(
            shardCount: 4,
            forcedPlacementValue:
                QuicConnectionShardPlacementPolicyValue
                    .BoundedPowerOfTwoChoices);
        QuicConnectionRuntime runtime =
            new(QuicConnectionStreamStateTestHelpers.CreateState());
        runtime.ConfigureAdaptiveRuntimePolicy(
            new QuicClientConnectionOptions
            {
                ConnectionShardPlacementEvidenceSink =
                    new ThrowingPlacementSink(),
            });
        QuicConnectionHandle handle = new(17);

        Assert.True(host.TryRegisterConnection(handle, runtime));
        Assert.True(host.TryGetPlacementDecision(
            handle,
            out QuicConnectionShardPlacementDecision decision));
        Assert.Equal(decision.AppliedShardIndex, host.GetShardIndex(handle));

        Assert.True(host.TryUnregisterConnection(handle));
        await runtime.DisposeAsync();
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void InvalidClosedValuesAreRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicConnectionShardPlacementPolicy.ValidateValue(
                (QuicConnectionShardPlacementPolicyValue)byte.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => QuicConnectionShardPlacementPolicy
                .ValidateObservationMode(
                    (QuicConnectionShardPlacementObservationMode)
                        byte.MaxValue));
        Assert.Throws<ArgumentOutOfRangeException>(
            () => new QuicConnectionRuntimeHost(
                4,
                placementObservationMode:
                    (QuicConnectionShardPlacementObservationMode)
                        byte.MaxValue));
    }

    private sealed class RecordingPlacementSink :
        IQuicConnectionShardPlacementEvidenceSink
    {
        internal List<QuicConnectionShardPlacementDecision> Decisions
        {
            get;
        } = [];

        public bool TryPublish(
            in QuicConnectionShardPlacementDecision decision)
        {
            Decisions.Add(decision);
            return true;
        }
    }

    private sealed class ThrowingPlacementSink :
        IQuicConnectionShardPlacementEvidenceSink
    {
        public bool TryPublish(
            in QuicConnectionShardPlacementDecision decision)
            => throw new InvalidOperationException("expected");
    }
}
