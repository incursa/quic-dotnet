// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0002")]
public sealed class REQ_QUIC_RFC9000_S9P4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PathValidationMustCompleteBeforeOldPathRecoveryStateIsReset()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.20", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.21", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, candidatePath, datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(candidatePath, out QuicConnectionCandidatePathRecord candidate));
        Assert.False(candidate.Validation.IsValidated);
        Assert.False(candidate.Validation.IsAbandoned);
        Assert.Equal(1UL, candidate.Validation.ChallengeSendCount);
        Assert.True(candidate.Validation.ValidationDeadlineTicks.HasValue);
        QuicPathMigrationRecoverySnapshot afterCandidateProbe =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);
        Assert.Equal(dirty.PendingRetransmissionCount, afterCandidateProbe.PendingRetransmissionCount);
        Assert.Equal(dirty.HasAckElicitingPacketsInFlight, afterCandidateProbe.HasAckElicitingPacketsInFlight);
        Assert.Equal(dirty.LossDetectionDeadlineMicros, afterCandidateProbe.LossDetectionDeadlineMicros);
        Assert.Equal(dirty.ProbeTimeoutCount, afterCandidateProbe.ProbeTimeoutCount);
        Assert.Equal(dirty.CongestionWindowBytes, afterCandidateProbe.CongestionWindowBytes);
        Assert.Equal(dirty.SlowStartThresholdBytes, afterCandidateProbe.SlowStartThresholdBytes);
        Assert.Equal(dirty.RecoveryStartTimeMicros, afterCandidateProbe.RecoveryStartTimeMicros);
        Assert.Equal(dirty.SmoothedRttMicros, afterCandidateProbe.SmoothedRttMicros);
        Assert.Equal(dirty.RttVarMicros, afterCandidateProbe.RttVarMicros);
        Assert.Equal(dirty.EcnValidated, afterCandidateProbe.EcnValidated);
        Assert.Equal(dirty.SentPacketCount, afterCandidateProbe.SentPacketCount);
        Assert.Equal(dirty.BytesInFlightBytes, afterCandidateProbe.BytesInFlightBytes);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            candidatePath,
            runtime: runtime);
    }
}
