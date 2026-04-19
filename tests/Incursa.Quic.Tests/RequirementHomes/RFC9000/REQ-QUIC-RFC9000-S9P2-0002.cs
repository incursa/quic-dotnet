namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P2-0002")]
public sealed class REQ_QUIC_RFC9000_S9P2_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TheRuntimeInitiatesPathValidationOnTheNewLocalAddress()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.40",
            LocalAddress: "198.51.100.40",
            RemotePort: 443,
            LocalPort: 61264);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.40",
            LocalAddress: "198.51.100.41",
            RemotePort: 443,
            LocalPort: 61265);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Contains(receiveResult.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == migratedPath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
    }
}
