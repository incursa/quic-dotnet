// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S9-3-P3-S1-R01")]
public sealed class RFC9000_S9_3_P3_S1_R01
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationPromotesTheMigratedPathBeforeTheNextReplyPacket()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.74", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.75", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PathValidationOnlyPacketsDoNotSwitchStreamPacketsToTheMigratedAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.76", RemotePort: 443);
        using QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicConnectionPathIdentity migratedPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };
        byte[] challengeData = QuicS8P2PathValidationTestSupport.CreateChallengeData(0x63);
        byte[] pathChallengePayload = QuicFrameTestData.BuildPathChallengeFrame(new QuicPathChallengeFrame(challengeData));

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult probingResult =
            QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
                runtime,
                migratedPath,
                runtime.CurrentPeerDestinationConnectionId.Span,
                pathChallengePayload,
                observedAtTicks: 30);

        Assert.True(probingResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.False(candidatePath.HasHighestNonProbingPacketNumber);

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(activePath, send.PathIdentity);
        Assert.DoesNotContain(probingResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_SendAddressOnlyChangesForTheHighestNonProbingMigratedPacket()
    {
        for (int iteration = 0; iteration < 4; iteration++)
        {
            QuicConnectionPathIdentity activePath = new(
                $"203.0.113.{90 + iteration}",
                $"198.51.100.{90 + iteration}",
                RemotePort: 443,
                LocalPort: 61200 + iteration);
            using QuicConnectionRuntime runtime =
                QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
            QuicConnectionPathIdentity migratedPath = activePath with
            {
                RemoteAddress = $"203.0.113.{110 + iteration}",
                RemotePort = 6443 + iteration,
            };

            QuicConnectionTransitionResult receiveResult = ReceiveNonProbingStreamPacket(
                runtime,
                migratedPath,
                streamId: (ulong)(iteration * 4),
                observedAtTicks: 40 + iteration);

            Assert.True(receiveResult.StateChanged);
            Assert.True(runtime.CandidatePaths.TryGetValue(
                migratedPath,
                out QuicConnectionCandidatePathRecord nonProbingCandidate));
            Assert.True(nonProbingCandidate.HasHighestNonProbingPacketNumber);
            Assert.DoesNotContain(receiveResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                runtime,
                migratedPath,
                observedAtTicks: 60 + iteration);

            Assert.True(validationResult.StateChanged);
            Assert.True(runtime.ActivePath.HasValue);
            Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);

            QuicConnectionSendDatagramEffect send =
                await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

            Assert.Equal(migratedPath, send.PathIdentity);
        }
    }

    private static QuicConnectionTransitionResult ReceiveNonProbingStreamPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        ulong streamId,
        long observedAtTicks)
    {
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId,
            streamData: [0x41],
            offset: 0);
        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            pathIdentity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            streamFrame,
            observedAtTicks);
    }
}
