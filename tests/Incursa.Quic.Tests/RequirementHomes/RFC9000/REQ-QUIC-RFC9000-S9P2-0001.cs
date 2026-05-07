namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P2-0001")]
public sealed class REQ_QUIC_RFC9000_S9P2_0001
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
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RecentlyValidatedPathDefersPromotionWhenItReceivesApplicationData()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
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
}
