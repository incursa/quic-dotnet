// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0476")]
public sealed class REQ_QUIC_RFC9000_0476
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ReplyTrafficStaysOnTheOriginalPathWhileValidationIsPending()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.30",
            LocalAddress: "198.51.100.30",
            RemotePort: 443,
            LocalPort: 61254);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.30",
            LocalAddress: "198.51.100.31",
            RemotePort: 443,
            LocalPort: 61255);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult replyResult = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 30,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Contains(replyResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == activePath);
        Assert.DoesNotContain(replyResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedPathCanBePromotedAfterTheNextNonProbingFrameArrives()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.32", RemotePort: 443);
        using QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicConnectionPathIdentity migratedPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 0,
            streamData: [0x41],
            offset: 0);

        QuicConnectionTransitionResult receiveResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            migratedPath,
            runtime.CurrentPeerDestinationConnectionId.Span,
            streamFrame,
            observedAtTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.True(candidatePath.HasHighestNonProbingPacketNumber);

        QuicConnectionTransitionResult promotionResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(promotionResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(promotionResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecentlyValidatedPathDefersPromotionWhenItReceivesApplicationData()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity firstValidatedPath = new(
            RemoteAddress: "203.0.113.31",
            LocalAddress: "198.51.100.31",
            RemotePort: 443,
            LocalPort: 61256);
        QuicConnectionPathIdentity secondValidatedPath = new(
            RemoteAddress: "203.0.113.31",
            LocalAddress: "198.51.100.32",
            RemotePort: 443,
            LocalPort: 61257);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstValidatedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            firstValidatedPath,
            observedAtTicks: 30).StateChanged);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                secondValidatedPath,
                datagram),
            nowTicks: 40).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            secondValidatedPath,
            observedAtTicks: 50).StateChanged);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(secondValidatedPath, runtime.ActivePath!.Value.Identity);

        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);
        byte[] applicationPayload = QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [0x11, 0x22]);
        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x09],
            applicationPayload,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial.Value,
            declaredPacketNumberLength: 4);

        QuicConnectionTransitionResult edgeResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 60,
                firstValidatedPath,
                protectedPacket),
            nowTicks: 60);

        Assert.True(edgeResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(secondValidatedPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(firstValidatedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(0UL, candidatePath.Validation.ChallengeSendCount);
        Assert.DoesNotContain(edgeResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    [Requirement("REQ-QUIC-RFC9000-0467")]
    [Requirement("REQ-QUIC-RFC9000-0468")]
    [Requirement("REQ-QUIC-RFC9000-0476")]
    [Requirement("RFC9000-S9-P3-S2-R01")]
    [Requirement("RFC9000-S9-P5-S2-R01")]
    public void Fuzz_MigrationPolicyKeepsTrafficOnEligiblePathsUntilValidationCompletes()
    {
        for (int iteration = 0; iteration < 6; iteration++)
        {
            using QuicConnectionRuntime clientRuntime =
                QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
            Assert.True(clientRuntime.ActivePath.HasValue);

            QuicConnectionPathIdentity clientActivePath = clientRuntime.ActivePath.Value.Identity;
            QuicConnectionPathIdentity unexpectedServerPath = clientActivePath with
            {
                RemoteAddress = $"203.0.113.{90 + iteration}",
                RemotePort = (ushort)(9443 + iteration),
            };
            byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
                clientRuntime.CurrentPeerDestinationConnectionId.Span,
                [0x00, 0x00, 0x00, (byte)(0x30 + iteration)],
                QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 1, [(byte)(0x20 + iteration)]),
                clientRuntime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                declaredPacketNumberLength: 4);

            QuicConnectionTransitionResult discardResult = clientRuntime.Transition(
                new QuicConnectionPacketReceivedEvent(
                    ObservedAtTicks: 20 + iteration,
                    unexpectedServerPath,
                    protectedPacket),
                nowTicks: 20 + iteration);

            Assert.Equal(clientActivePath, clientRuntime.ActivePath!.Value.Identity);
            Assert.False(clientRuntime.CandidatePaths.ContainsKey(unexpectedServerPath));
            Assert.False(clientRuntime.RecentlyValidatedPaths.ContainsKey(unexpectedServerPath));
            Assert.DoesNotContain(discardResult.Effects, effect =>
                effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == unexpectedServerPath);
            Assert.DoesNotContain(discardResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == unexpectedServerPath);

            QuicConnectionPathIdentity serverActivePath = new($"203.0.113.{120 + iteration}", RemotePort: 443);
            QuicConnectionPathIdentity migratedClientPath = serverActivePath with
            {
                RemotePort = (ushort)(5443 + iteration),
            };
            using QuicConnectionRuntime serverRuntime =
                QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(serverActivePath);
            byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
                0x0E,
                streamId: 0,
                streamData: [(byte)(0x41 + iteration)],
                offset: 0);

            QuicConnectionTransitionResult pendingMigrationResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
                serverRuntime,
                migratedClientPath,
                serverRuntime.CurrentPeerDestinationConnectionId.Span,
                streamFrame,
                observedAtTicks: 40 + iteration);

            Assert.True(pendingMigrationResult.StateChanged);
            Assert.True(serverRuntime.ActivePath.HasValue);
            Assert.Equal(serverActivePath, serverRuntime.ActivePath!.Value.Identity);
            Assert.True(serverRuntime.CandidatePaths.TryGetValue(
                migratedClientPath,
                out QuicConnectionCandidatePathRecord candidatePath));
            Assert.False(candidatePath.Validation.IsValidated);
            Assert.False(candidatePath.Validation.IsAbandoned);
            Assert.True(candidatePath.HasHighestNonProbingPacketNumber);
            Assert.DoesNotContain(pendingMigrationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedClientPath);

            QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
                serverRuntime,
                migratedClientPath,
                observedAtTicks: 60 + iteration);

            Assert.True(validationResult.StateChanged);
            Assert.True(serverRuntime.ActivePath.HasValue);
            Assert.Equal(migratedClientPath, serverRuntime.ActivePath!.Value.Identity);
            Assert.Contains(validationResult.Effects, effect =>
                effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedClientPath);
        }
    }
}
