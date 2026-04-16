namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0002")]
public sealed class REQ_QUIC_RFC9000_S9P3_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void UnvalidatedPeerAddressCanReceiveAPathValidationChallengeBeforePromotion()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.100", RemotePort: 443);
        QuicConnectionPathIdentity unvalidatedPath = new("203.0.113.101", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                unvalidatedPath,
                datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(unvalidatedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == unvalidatedPath);
    }
}
