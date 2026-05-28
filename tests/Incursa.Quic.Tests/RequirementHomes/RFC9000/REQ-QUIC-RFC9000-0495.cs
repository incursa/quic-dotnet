// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0495")]
public sealed class REQ_QUIC_RFC9000_0495
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationFailureWithoutALastValidatedPeerAddressDiscardsAllConnectionState()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(new("203.0.113.19", RemotePort: 443));
        Assert.False(runtime.HasValidatedPath);
        Assert.Null(runtime.LastValidatedRemoteAddress);
        Assert.Empty(runtime.CandidatePaths);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 20,
                new QuicConnectionPathIdentity("203.0.113.20", RemotePort: 443),
                IsAbandoned: true),
            nowTicks: 20);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.TerminalState.Value.Phase);
        Assert.Contains(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ValidationFailureWithoutAnyValidatedPathDiscardsTheConnectionSilently()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(new("203.0.113.20", RemotePort: 443));
        Assert.False(runtime.HasValidatedPath);
        Assert.Null(runtime.LastValidatedRemoteAddress);
        Assert.Empty(runtime.CandidatePaths);

        QuicConnectionPathIdentity failedPath = new("203.0.113.21", RemotePort: 443);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: 20,
                failedPath,
                IsAbandoned: true),
            nowTicks: 20);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.None, runtime.SendingMode);
        Assert.False(runtime.CanSendOrdinaryPackets);
        Assert.True(runtime.TerminalState.HasValue);
        Assert.Equal(QuicConnectionPhase.Discarded, runtime.TerminalState.Value.Phase);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal("203.0.113.20", runtime.ActivePath!.Value.Identity.RemoteAddress);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        Assert.Contains(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
    }
}
