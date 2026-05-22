namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0499")]
public sealed class REQ_QUIC_RFC9000_0499
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0499")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PacketFromANewAddressStartsPathValidationWithAChallenge()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.70", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.71", RemotePort: 443);
        QuicConnectionRuntime runtime =
            QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.False(candidatePath.Validation.IsAbandoned);
        Assert.Equal(1UL, candidatePath.Validation.ChallengeSendCount);
        Assert.True(candidatePath.Validation.ValidationDeadlineTicks.HasValue);
        Assert.Equal(QuicPathValidation.PathChallengeDataLength, candidatePath.Validation.ChallengePayload.Length);
        Assert.True(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.PathValidation).HasValue);

        QuicS8P2PathValidationTestSupport.AssertSinglePathChallengeDatagram(
            result,
            migratedPath,
            runtime: runtime);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }
}
