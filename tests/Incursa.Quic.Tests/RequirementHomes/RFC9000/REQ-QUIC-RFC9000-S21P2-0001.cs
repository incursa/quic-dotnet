namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S21P2-0001")]
public sealed class REQ_QUIC_RFC9000_S21P2_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ChangedPeerAddressDuringHandshakeKeepsTheOriginalActivePath()
    {
        QuicConnectionPathIdentity originalPath = new("203.0.113.240", RemotePort: 443);
        QuicConnectionRuntime runtime = CreateRuntimeWithHandshakePendingActivePath(originalPath);
        QuicConnectionPathIdentity changedPath = new("203.0.113.241", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                changedPath,
                datagram),
            nowTicks: 20);

        Assert.True(result.StateChanged);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(changedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(result.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ChangedPeerAddressAfterHandshakeTranscriptCompletionStartsMigrationHandling()
    {
        QuicPathMigrationRecoveryTestSupport.AssertChangedPeerAddressStartsPathValidationBeforePromotion(
            activePath: new("203.0.113.242", RemotePort: 443),
            changedPeerAddressPath: new("203.0.113.243", RemotePort: 443),
            observedAtTicks: 20);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S21P2-0001")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void ChangedPeerAddressAtTheHandshakeCompletionBoundaryCanPromoteAfterValidation()
    {
        QuicConnectionPathIdentity originalPath = new("203.0.113.244", RemotePort: 443);
        QuicConnectionRuntime runtime = CreateRuntimeWithHandshakePendingActivePath(originalPath);
        QuicConnectionPathIdentity changedPath = new("203.0.113.245", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPeerHandshakeTranscriptCompletedEvent(ObservedAtTicks: 30),
            nowTicks: 30).StateChanged);
        Assert.True(runtime.PeerHandshakeTranscriptCompleted);

        QuicConnectionTransitionResult receiveResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 31,
                changedPath,
                datagram),
            nowTicks: 31);

        Assert.True(receiveResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(changedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(receiveResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            changedPath,
            observedAtTicks: 32).StateChanged);
        Assert.Equal(changedPath, runtime.ActivePath!.Value.Identity);
    }

    private static QuicConnectionRuntime CreateRuntimeWithHandshakePendingActivePath(QuicConnectionPathIdentity activePath)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntime();
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                activePath,
                datagram),
            nowTicks: 10).StateChanged);
        Assert.False(runtime.PeerHandshakeTranscriptCompleted);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);

        return runtime;
    }
}
