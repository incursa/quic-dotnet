// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="RFC9000-S14-2-P4-S2-R01">An endpoint MAY terminate the connection if an alternative path cannot be found.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S14-2-P4-S2-R01")]
public sealed class REQ_QUIC_RFC9000_0872
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PathValidationFailureWithoutAnyValidatedPathDiscardsTheConnection()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        QuicConnectionPathIdentity failedPath = new("203.0.113.208", RemotePort: 443);

        Assert.False(runtime.HasValidatedPath);
        Assert.Null(runtime.ActivePath);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 20,
                failedPath,
                IsAbandoned: true),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.TerminalState.Value.Phase);
        Assert.Equal(QuicConnectionCloseOrigin.Remote, runtime.TerminalState.Value.Origin);
        Assert.Contains(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathValidationFailureDoesNotDiscardWhileAValidatedPathRemainsAvailable()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity failedPath = new("203.0.113.210", RemotePort: 443);

        Assert.True(runtime.HasValidatedPath);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 30,
                failedPath,
                IsAbandoned: true),
            nowTicks: 30);

        Assert.False(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Null(runtime.TerminalState);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathValidationFailureFuzz_TerminatesOnlyWhenNoValidatedAlternativePathExists()
    {
        for (int index = 0; index < 8; index++)
        {
            QuicConnectionPathIdentity failedPath = new(
                $"203.0.113.{220 + index}",
                RemotePort: 443 + index);

            QuicConnectionRuntime noAlternativeRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();

            QuicConnectionTransitionResult noAlternativeResult = noAlternativeRuntime.Transition(
                new QuicConnectionPathValidationFailedEvent(
                    ObservedAtTicks: 40 + index,
                    failedPath,
                    IsAbandoned: true),
                nowTicks: 40 + index);

            Assert.True(noAlternativeResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Discarded, noAlternativeRuntime.Phase);
            Assert.Equal(QuicConnectionSendingMode.None, noAlternativeRuntime.SendingMode);
            Assert.Contains(
                noAlternativeResult.Effects,
                effect => effect is QuicConnectionDiscardConnectionStateEffect);

            QuicConnectionRuntime validatedAlternativeRuntime =
                QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            QuicConnectionPathIdentity validatedPath = validatedAlternativeRuntime.ActivePath!.Value.Identity;

            QuicConnectionTransitionResult validatedAlternativeResult = validatedAlternativeRuntime.Transition(
                new QuicConnectionPathValidationFailedEvent(
                    ObservedAtTicks: 80 + index,
                    failedPath,
                    IsAbandoned: true),
                nowTicks: 80 + index);

            Assert.False(validatedAlternativeResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Active, validatedAlternativeRuntime.Phase);
            Assert.Equal(QuicConnectionSendingMode.Ordinary, validatedAlternativeRuntime.SendingMode);
            Assert.Equal(validatedPath, validatedAlternativeRuntime.ActivePath!.Value.Identity);
            Assert.Null(validatedAlternativeRuntime.TerminalState);
            Assert.DoesNotContain(
                validatedAlternativeResult.Effects,
                effect => effect is QuicConnectionDiscardConnectionStateEffect);
        }
    }
}
