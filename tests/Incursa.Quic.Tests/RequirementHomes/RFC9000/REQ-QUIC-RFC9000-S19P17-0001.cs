namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P17-0001">Endpoints MAY use PATH_CHALLENGE frames (type=0x1a) to check reachability to the peer and for path validation during connection migration.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S19P17-0001")]
public sealed class REQ_QUIC_RFC9000_S19P17_0001
{
    private static readonly QuicConnectionPathIdentity OriginalPath = new("203.0.113.70", RemotePort: 443);
    private static readonly QuicConnectionPathIdentity MigratedPath = new("203.0.113.71", RemotePort: 443);

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketFromANewAddressUsesPathChallengeToStartMigrationValidation()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                MigratedPath,
                datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(OriginalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(MigratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);

        QuicConnectionSendDatagramEffect send = Assert.Single(result.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(MigratedPath, send.PathIdentity);
        Assert.True(QuicFrameCodec.TryParsePathChallengeFrame(
            send.Datagram.Span,
            out QuicPathChallengeFrame parsedChallenge,
            out int bytesConsumed));
        Assert.Equal(QuicPathValidation.PathChallengeDataLength + 1, bytesConsumed);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, parsedChallenge.Data.Length);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P17-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void RepeatedPacketsDoNotRestartPathChallengeValidationWhileTheChallengeIsPending()
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(OriginalPath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult firstResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                MigratedPath,
                datagram),
            nowTicks: 20);

        Assert.Contains(firstResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect sendDatagramEffect
            && sendDatagramEffect.PathIdentity == MigratedPath
            && QuicFrameCodec.TryParsePathChallengeFrame(sendDatagramEffect.Datagram.Span, out _, out _));

        Assert.True(runtime.CandidatePaths.TryGetValue(MigratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        long? validationDeadline = candidatePath.Validation.ValidationDeadlineTicks;

        QuicConnectionTransitionResult repeatResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                MigratedPath,
                datagram),
            nowTicks: 30);

        Assert.True(runtime.CandidatePaths.TryGetValue(MigratedPath, out QuicConnectionCandidatePathRecord repeatedCandidatePath));
        Assert.Equal(1UL, repeatedCandidatePath.Validation.ChallengeSendCount);
        Assert.Equal(validationDeadline, repeatedCandidatePath.Validation.ValidationDeadlineTicks);
        Assert.DoesNotContain(repeatResult.Effects, effect => effect is QuicConnectionSendDatagramEffect);
    }
}
