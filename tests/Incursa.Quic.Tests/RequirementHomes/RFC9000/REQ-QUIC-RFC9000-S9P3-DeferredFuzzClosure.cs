// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S9P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3-0001")]
    [Requirement("REQ-QUIC-RFC9000-S9P3-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PermittedMigrationFuzz_StartsPathValidationAndRoutesSubsequentPacketsAfterValidation()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                RemoteAddress: $"203.0.113.{100 + iteration}",
                RemotePort: 443);
            QuicConnectionPathIdentity migratedPath = new(
                RemoteAddress: $"203.0.113.{120 + iteration}",
                RemotePort: 443 + iteration);
            QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

            QuicConnectionTransitionResult migrationResult = runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20,
                    migratedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 20);

            Assert.True(migrationResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
            Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
            Assert.DoesNotContain(migrationResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
            QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
                migrationResult,
                migratedPath,
                runtime: runtime);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 30);

            QuicConnectionTransitionResult closeResult = runtime.Transition(
                new QuicConnectionLocalCloseRequestedEvent(
                    ObservedAtTicks: 40,
                    QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
                nowTicks: 40);

            Assert.True(validationResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
            Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);
            Assert.Contains(closeResult.Effects, effect =>
                effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == migratedPath);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PendingPathValidationFuzz_CanAbandonStaleValidationAfterAnotherPathIsPromoted()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                RemoteAddress: $"203.0.113.{140 + iteration}",
                RemotePort: 443);
            QuicConnectionPathIdentity staleCandidatePath = new(
                RemoteAddress: $"203.0.113.{160 + iteration}",
                RemotePort: 443);
            QuicConnectionPathIdentity promotedPath = new(
                RemoteAddress: $"203.0.113.{180 + iteration}",
                RemotePort: 443);
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
            byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, staleCandidatePath, datagram),
                nowTicks: 20).StateChanged);
            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 30, promotedPath, datagram),
                nowTicks: 30).StateChanged);

            Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                promotedPath,
                observedAtTicks: 40).StateChanged);

            QuicConnectionTransitionResult abandonResult = runtime.Transition(
                new QuicConnectionPathValidationFailedEvent(
                    ObservedAtTicks: 50,
                    staleCandidatePath,
                    IsAbandoned: true),
                nowTicks: 50);

            Assert.True(abandonResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(promotedPath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(staleCandidatePath, out QuicConnectionCandidatePathRecord staleCandidate));
            Assert.False(staleCandidate.Validation.IsValidated);
            Assert.True(staleCandidate.Validation.IsAbandoned);
            Assert.Null(staleCandidate.Validation.ValidationDeadlineTicks);
            Assert.DoesNotContain(abandonResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        }
    }
}
