// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P2-0004")]
public sealed class REQ_QUIC_RFC9000_S9P3P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationFailureKeepsUsingTheMostRecentlyValidatedPeerAddress()
    {
        AssertValidationFailureKeepsUsingTheMostRecentlyValidatedPeerAddress(
            migratedValidatedPath: new("203.0.113.22", RemotePort: 443),
            failedPath: new("203.0.113.23", RemotePort: 443),
            tickOffset: 20);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P2-0004")]
    public void Fuzz_ValidationFailureRevertsAcrossSampledLastValidatedPeerAddresses()
    {
        for (int index = 0; index < 4; index++)
        {
            AssertValidationFailureKeepsUsingTheMostRecentlyValidatedPeerAddress(
                migratedValidatedPath: new($"203.0.113.{30 + (index * 2)}", RemotePort: 443 + index),
                failedPath: new($"203.0.113.{31 + (index * 2)}", RemotePort: 1443 + index),
                tickOffset: 100 + (index * 40));
        }
    }

    private static void AssertValidationFailureKeepsUsingTheMostRecentlyValidatedPeerAddress(
        QuicConnectionPathIdentity migratedValidatedPath,
        QuicConnectionPathIdentity failedPath,
        long tickOffset)
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity originalValidatedPath = runtime.ActivePath!.Value.Identity;
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: tickOffset,
                migratedValidatedPath,
                datagram),
            nowTicks: tickOffset).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedValidatedPath, out QuicConnectionCandidatePathRecord migratedCandidatePath));
        Assert.False(migratedCandidatePath.Validation.IsValidated);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedValidatedPath,
            observedAtTicks: tickOffset + 10);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(originalValidatedPath));
        Assert.True(runtime.RecentlyValidatedPaths.ContainsKey(migratedValidatedPath));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedValidatedPath
            && !promote.RestoreSavedState);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: tickOffset + 20,
                failedPath,
                datagram),
            nowTicks: tickOffset + 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out QuicConnectionCandidatePathRecord failedCandidatePath));
        Assert.False(failedCandidatePath.Validation.IsValidated);
        Assert.False(failedCandidatePath.Validation.IsAbandoned);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: tickOffset + 30,
                failedPath,
                IsAbandoned: true),
            nowTicks: tickOffset + 30);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out failedCandidatePath));
        Assert.True(failedCandidatePath.Validation.IsAbandoned);
        Assert.False(failedCandidatePath.Validation.IsValidated);
        Assert.Null(failedCandidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
