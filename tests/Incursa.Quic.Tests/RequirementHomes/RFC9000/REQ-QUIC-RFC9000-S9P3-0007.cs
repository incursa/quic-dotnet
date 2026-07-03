// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0007")]
public sealed class REQ_QUIC_RFC9000_S9P3_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketFromANewAddressStartsPathValidationWhenMigrationIsPermitted()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.70", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.71", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            migratedPath,
            runtime: runtime);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PacketFromANewAddressBeforeOneRttProtectionDoesNotSendARawPathChallenge()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.72", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.73", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePathBeforeHandshakeConfirmation(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(0UL, candidatePath.Validation.ChallengeSendCount);
        Assert.Null(candidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedPacketsDoNotRestartPathValidationWhileTheChallengeIsPending()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.80", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.81", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, migratedPath, datagram),
            nowTicks: 20);

        Assert.Contains(firstResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        long? validationDeadline = candidatePath.Validation.ValidationDeadlineTicks;

        QuicConnectionTransitionResult repeatResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 30, migratedPath, datagram),
            nowTicks: 30);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord repeatedCandidatePath));
        Assert.Equal(1UL, repeatedCandidatePath.Validation.ChallengeSendCount);
        Assert.Equal(validationDeadline, repeatedCandidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(repeatResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0483")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ASecondMigratedAddressStartsValidationWhileTheFirstChallengeIsPending()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.82", RemotePort: 443);
        QuicConnectionPathIdentity firstMigratedPath = new("203.0.113.83", RemotePort: 443);
        QuicConnectionPathIdentity secondMigratedPath = new("203.0.113.84", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, firstMigratedPath, datagram),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult edgeResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 30, secondMigratedPath, datagram),
            nowTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(firstMigratedPath, out QuicConnectionCandidatePathRecord firstCandidatePath));
        Assert.True(runtime.CandidatePaths.TryGetValue(secondMigratedPath, out QuicConnectionCandidatePathRecord secondCandidatePath));
        Assert.Equal(1UL, firstCandidatePath.Validation.ChallengeSendCount);
        Assert.Equal(1UL, secondCandidatePath.Validation.ChallengeSendCount);
        Assert.Contains(edgeResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == secondMigratedPath);
        Assert.DoesNotContain(edgeResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TinyPacketFromASecondPortRebindStillStartsPathValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.85", RemotePort: 443);
        QuicConnectionPathIdentity firstPortRebindPath = new("203.0.113.85", RemotePort: 8443);
        QuicConnectionPathIdentity secondPortRebindPath = new("203.0.113.85", RemotePort: 9443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstPortRebindPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);
        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            firstPortRebindPath,
            observedAtTicks: 30).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(firstPortRebindPath, runtime.ActivePath!.Value.Identity);

        for (ulong packetNumber = 1; packetNumber < 64; packetNumber += 2)
        {
            runtime.SendRuntime.FlowController.RecordIncomingPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                ackEliciting: true,
                receivedAtMicros: packetNumber);
        }

        const int tinyRebindPacketBytes = 32;
        QuicConnectionTransitionResult secondRebindResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                secondPortRebindPath,
                new byte[tinyRebindPacketBytes]),
            nowTicks: 40);

        Assert.True(secondRebindResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(secondPortRebindPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);

        QuicConnectionSendDatagramEffect send = Assert.Single(secondRebindResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(secondPortRebindPath, send.PathIdentity);
        Assert.True(send.Datagram.Length <= tinyRebindPacketBytes * 3);
        Assert.True(QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
            runtime,
            send.Datagram.Span,
            out _,
            out _,
            out _));
        Assert.DoesNotContain(secondRebindResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
    [Requirement("RFC9002-S7-5-P1-S1-R01")]
    [Requirement("REQ-QUIC-RFC9002-S7P5-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PathChallengeForASecondPortRebindBypassesAFullCongestionWindow()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.86", RemotePort: 443);
        QuicConnectionPathIdentity firstPortRebindPath = new("203.0.113.86", RemotePort: 8443);
        QuicConnectionPathIdentity secondPortRebindPath = new("203.0.113.86", RemotePort: 9443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                firstPortRebindPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);
        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            firstPortRebindPath,
            observedAtTicks: 30).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(firstPortRebindPath, runtime.ActivePath!.Value.Identity);

        ulong congestionWindowBytes = runtime.SendRuntime.FlowController.CongestionControlState.CongestionWindowBytes;
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 10_000,
            PayloadBytes: congestionWindowBytes,
            SentAtMicros: 35,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt));
        ulong bytesInFlightBeforeProbe =
            runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes;
        Assert.False(runtime.SendRuntime.FlowController.CanSend(
            QuicPacketNumberSpace.ApplicationData,
            sentBytes: 1));

        const int tinyRebindPacketBytes = 32;
        QuicConnectionTransitionResult secondRebindResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 40,
                secondPortRebindPath,
                new byte[tinyRebindPacketBytes]),
            nowTicks: 40);

        Assert.True(secondRebindResult.StateChanged);
        Assert.True(runtime.CandidatePaths.TryGetValue(secondPortRebindPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);

        QuicConnectionSendDatagramEffect send = Assert.Single(secondRebindResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(secondPortRebindPath, send.PathIdentity);
        Assert.True(send.Datagram.Length <= tinyRebindPacketBytes * 3);
        Assert.True(QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
            runtime,
            send.Datagram.Span,
            out _,
            out _,
            out _));
        Assert.Equal(bytesInFlightBeforeProbe, runtime.SendRuntime.FlowController.CongestionControlState.BytesInFlightBytes);
        Assert.DoesNotContain(secondRebindResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
