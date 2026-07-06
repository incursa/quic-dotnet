// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_MigrationPath_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0447")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathChallengeResponseFuzz_EmitsExactlyOnePathResponseForEachChallenge()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
            QuicConnectionPathIdentity challengePath = new($"203.0.113.{60 + iteration}", RemotePort: (ushort)(4400 + iteration));
            byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData((byte)(0x20 + iteration));

            QuicConnectionTransitionResult result = QuicS8P2PathValidationTestSupport.ReceiveProtectedPathChallenge(
                runtime,
                challengePath,
                challengeData,
                packetNumber: (byte)(0x10 + iteration),
                observedAtTicks: 10 + iteration,
                includePing: iteration % 2 == 0);

            Assert.True(result.StateChanged);
            QuicConnectionSendDatagramEffect response = QuicS8P2PathValidationTestSupport.AssertSinglePathResponseDatagram(
                runtime,
                result,
                challengePath,
                challengeData,
                expectMinimumSize: false);
            Assert.Equal(challengePath, response.PathIdentity);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0475")]
    [Requirement("REQ-QUIC-RFC9000-0476")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PathValidationPromotionFuzz_StartsValidationAndPromotesOnlyAfterValidationSucceeds()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new($"203.0.113.{80 + iteration}", RemotePort: 443);
            QuicConnectionPathIdentity migratedPath = activePath with
            {
                RemotePort = activePath.RemotePort + 100 + iteration,
            };
            using QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);

            byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
                0x0E,
                streamId: 0,
                streamData: [(byte)(0x41 + iteration)],
                offset: 0);

            QuicConnectionTransitionResult receiveResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
                runtime,
                migratedPath,
                runtime.CurrentPeerDestinationConnectionId.Span,
                streamFrame,
                observedAtTicks: 20 + iteration);

            Assert.True(receiveResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
            Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.True(candidatePath.HasHighestNonProbingPacketNumber);
            Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
            QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
                receiveResult,
                migratedPath,
                expectMinimumSize: false,
                runtime: runtime);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 40 + iteration);

            Assert.True(validationResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0498")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void OriginalPathReturnFuzz_ReturnsOnlyWhenOriginalPathPacketNumberIncreases()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(runtime.ActivePath.HasValue);

            QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
            QuicConnectionPathIdentity migratedPath = new($"203.0.113.{100 + iteration}", RemotePort: (ushort)(443 + iteration));

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10 + iteration,
                    migratedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 10 + iteration).StateChanged);
            Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, migratedPath, observedAtTicks: 20 + iteration).StateChanged);
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);

            _ = SendProtectedPing(runtime, migratedPath, packetNumber: (ushort)(0x100 + iteration), observedAtTicks: 30 + iteration);

            QuicConnectionTransitionResult staleOriginalPacket = SendProtectedPing(
                runtime,
                originalPath,
                packetNumber: (ushort)(0x0F0 + iteration),
                observedAtTicks: 40 + iteration);

            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
            Assert.DoesNotContain(staleOriginalPacket.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == originalPath);

            QuicConnectionTransitionResult newerOriginalPacket = SendProtectedPing(
                runtime,
                originalPath,
                packetNumber: (ushort)(0x101 + iteration),
                observedAtTicks: 50 + iteration);

            Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
            Assert.Contains(newerOriginalPacket.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == originalPath
                && !promote.RestoreSavedState);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0510")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void MultiPathAckFuzz_BuildsAckRangesForPacketsReceivedAcrossPaths()
    {
        for (int iteration = 0; iteration < 8; iteration++)
        {
            QuicConnectionPathIdentity activePath = new($"203.0.113.{120 + iteration}", RemotePort: 443);
            QuicConnectionPathIdentity migratedPath = new($"203.0.113.{130 + iteration}", RemotePort: 443);
            QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
            QuicSenderFlowController sender = runtime.SendRuntime.FlowController;

            ulong firstPacketNumber = (ulong)(1 + iteration);
            ulong secondPacketNumber = firstPacketNumber + 3;

            sender.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                firstPacketNumber,
                ackEliciting: true,
                receivedAtMicros: 1_000UL + (ulong)iteration);

            Assert.True(runtime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 10 + iteration,
                    migratedPath,
                    new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
                nowTicks: 10 + iteration).StateChanged);
            Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, migratedPath, observedAtTicks: 20 + iteration).StateChanged);
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);

            sender.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                secondPacketNumber,
                ackEliciting: true,
                receivedAtMicros: 2_000UL + (ulong)iteration);

            Assert.True(sender.TryBuildAckFrame(
                QuicPacketNumberSpace.ApplicationData,
                nowMicros: 2_100UL + (ulong)iteration,
                out QuicAckFrame frame));

            Assert.Equal(secondPacketNumber, frame.LargestAcknowledged);
            Assert.Equal(0UL, frame.FirstAckRange);
            QuicAckRange additionalRange = Assert.Single(frame.AdditionalRanges);
            Assert.Equal(1UL, additionalRange.Gap);
            Assert.Equal(0UL, additionalRange.AckRangeLength);
            Assert.Equal(firstPacketNumber, additionalRange.SmallestAcknowledged);
            Assert.Equal(firstPacketNumber, additionalRange.LargestAcknowledged);
            Assert.Equal(100UL, frame.AckDelay);
        }
    }

    private static QuicConnectionTransitionResult SendProtectedPing(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ushort packetNumber,
        long observedAtTicks)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        byte[] packetNumberBytes =
        [
            (byte)(packetNumber >> 8),
            (byte)packetNumber,
        ];
        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes,
            QuicFrameTestData.BuildPingFrame(),
            material,
            declaredPacketNumberLength: packetNumberBytes.Length);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }
}
