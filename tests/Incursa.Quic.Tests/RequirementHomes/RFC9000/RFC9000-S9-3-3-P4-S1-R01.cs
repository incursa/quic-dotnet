// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-3-3-P4-S1-R01")]
public sealed class REQ_QUIC_RFC9000_0499
{
    [Fact]
    [Requirement("RFC9000-S9-3-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketFromANewAddressStartsPathValidationWithAChallenge()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.70", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.71", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            migratedPath,
            runtime: runtime);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("RFC9000-S9-3-3-P4-S1-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PacketFromTheActiveAddressDoesNotStartPathValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.70", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                activePath,
                datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Empty(runtime.CandidatePaths);
        Assert.DoesNotContain(
            result.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
                runtime,
                effect.Datagram.Span,
                out _,
                out _,
                out _));
    }
}
