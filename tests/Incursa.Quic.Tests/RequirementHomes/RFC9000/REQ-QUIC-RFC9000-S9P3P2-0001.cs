// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P2-0001")]
public sealed class REQ_QUIC_RFC9000_S9P3P2_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidationFailureKeepsUsingTheLastValidatedPeerAddress()
    {
        AssertValidationFailureKeepsUsingTheLastValidatedPeerAddress(
            failedPath: new("203.0.113.21", RemotePort: 443),
            tickOffset: 20);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-S9P3P2-0001")]
    public void Fuzz_ValidationFailureKeepsUsingLastValidatedPeerAddressAcrossSampledFailedPaths()
    {
        for (int index = 0; index < 4; index++)
        {
            AssertValidationFailureKeepsUsingTheLastValidatedPeerAddress(
                failedPath: new($"203.0.113.{50 + index}", RemotePort: 443 + index),
                tickOffset: 100 + (index * 20));
        }
    }

    private static void AssertValidationFailureKeepsUsingTheLastValidatedPeerAddress(
        QuicConnectionPathIdentity failedPath,
        long tickOffset)
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity lastValidatedPath = runtime.ActivePath!.Value.Identity;
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: tickOffset,
                failedPath,
                datagram),
            nowTicks: tickOffset).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);

        QuicConnectionTransitionResult failureResult = runtime.Transition(
            new QuicConnectionPathValidationFailedEvent(
                ObservedAtTicks: tickOffset + 10,
                failedPath,
                IsAbandoned: true),
            nowTicks: tickOffset + 10);

        Assert.True(failureResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Equal(QuicConnectionSendingMode.Ordinary, runtime.SendingMode);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(lastValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(lastValidatedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.True(runtime.CandidatePaths.TryGetValue(failedPath, out candidatePath));
        Assert.True(candidatePath.Validation.IsAbandoned);
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.Null(candidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionDiscardConnectionStateEffect);
        Assert.DoesNotContain(failureResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
