// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0481")]
public sealed class REQ_QUIC_RFC9000_0481
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task NonProbingPacketFromPermittedMigrationRoutesStreamPacketsToTheMigratedAddressBeforeValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.72", RemotePort: 443);
        using QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicConnectionPathIdentity migratedPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord discoveredCandidatePath));
        Assert.False(discoveredCandidatePath.HasHighestNonProbingPacketNumber);

        QuicConnectionTransitionResult receiveResult = ReceiveNonProbingStreamPacket(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.True(candidatePath.HasHighestNonProbingPacketNumber);

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(migratedPath, send.PathIdentity);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task PermittedMigrationDoesNotRouteSubsequentStreamPacketsToTheOldPeerAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.82", RemotePort: 443);
        using QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicConnectionPathIdentity migratedPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };

        QuicConnectionTransitionResult receiveResult = ReceiveNonProbingStreamPacket(
            runtime,
            migratedPath,
            observedAtTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.HasHighestNonProbingPacketNumber);

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(migratedPath, send.PathIdentity);
        Assert.NotEqual(activePath, send.PathIdentity);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AckOnlyPacketFromPermittedMigrationRoutesStreamPacketsToTheMigratedAddressBeforeValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.78", RemotePort: 443);
        using QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicConnectionPathIdentity migratedPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 0,
            PayloadBytes: 1,
            SentAtMicros: 1,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));

        QuicConnectionTransitionResult receiveResult = ReceiveAckOnlyPacket(
            runtime,
            migratedPath,
            observedAtTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.True(candidatePath.HasHighestNonProbingPacketNumber);

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(migratedPath, send.PathIdentity);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task NonProbingMigrationSendCreditExhaustionQueuesStreamWritesUntilValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.77", RemotePort: 443);
        using QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateServerRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicConnectionPathIdentity migratedPath = activePath with
        {
            RemotePort = activePath.RemotePort + 1,
        };

        QuicConnectionTransitionResult receiveResult = ReceiveNonProbingStreamPacket(
            runtime,
            migratedPath,
            observedAtTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.True(candidatePath.HasHighestNonProbingPacketNumber);

        List<QuicConnectionEffect> writeEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent, nowTicks: 30);
            writeEffects.AddRange(transition.Effects);
            return true;
        });

        await runtime.WriteStreamAsync(1, new byte[512]);

        Assert.DoesNotContain(writeEffects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay).HasValue);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 40);

        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatedMigrationRoutesConnectionCloseRepliesToTheMigratedAddress()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.72", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.73", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        QuicConnectionTransitionResult replyResult = runtime.Transition(
            new QuicConnectionConnectionCloseFrameReceivedEvent(
                ObservedAtTicks: 40,
                QuicPathMigrationRecoveryTestSupport.CreateConnectionCloseMetadata()),
            nowTicks: 40);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Contains(replyResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);
    }

    private static QuicConnectionTransitionResult ReceiveNonProbingStreamPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        long observedAtTicks)
    {
        byte[] streamFrame = QuicStreamTestData.BuildStreamFrame(
            0x0E,
            streamId: 0,
            streamData: [0x41],
            offset: 0);
        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            pathIdentity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            streamFrame,
            observedAtTicks);
    }

    private static QuicConnectionTransitionResult ReceiveAckOnlyPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        long observedAtTicks)
    {
        byte[] ackFrame = QuicFrameTestData.BuildAckFrame(new QuicAckFrame
        {
            FrameType = 0x02,
            LargestAcknowledged = 0,
            AckDelay = 0,
            FirstAckRange = 0,
        });
        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            pathIdentity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            ackFrame,
            observedAtTicks);
    }
}
