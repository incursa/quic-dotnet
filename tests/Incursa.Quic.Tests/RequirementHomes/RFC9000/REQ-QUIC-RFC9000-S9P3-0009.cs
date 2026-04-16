namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3-0009")]
public sealed class REQ_QUIC_RFC9000_S9P3_0009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void SpoofedPeerAddressTrafficDoesNotReplaceTheLastValidatedAddressBeforeValidationSucceeds()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.107", RemotePort: 443);
        QuicConnectionPathIdentity spoofedPath = new("203.0.113.108", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                spoofedPath,
                datagram),
            nowTicks: 20);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(spoofedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == spoofedPath);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
