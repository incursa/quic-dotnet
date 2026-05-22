namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0475")]
public sealed class REQ_QUIC_RFC9000_0475
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
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.AddUnusedPeerConnectionId(runtime);
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
        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            receiveResult,
            migratedPath,
            runtime: runtime);
    }
}
