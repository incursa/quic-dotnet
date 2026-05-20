namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0001")]
public sealed class REQ_QUIC_RFC9000_S9P4_0001
{
    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void OldPathPacketsDoNotInfluenceTheNewPathsRecoveryStateAfterValidation()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);
        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 20).StateChanged);

        QuicPathMigrationRecoverySnapshot afterValidation = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                activePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 30);

        QuicPathMigrationRecoverySnapshot afterOldPathPacket = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(afterValidation, afterOldPathPacket);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatingANewPeerAddressRetransmitsRebuildableStreamDataOnTheNewPath()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] streamData = [0x51, 0x52, 0x53];
        byte[] streamPayload = QuicStreamTestData.BuildStreamFrame(0x0A, streamId: 0, streamData);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 64,
            SentAtMicros: 1_000,
            AckEliciting: true,
            Retransmittable: true,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            StreamIds: [0UL],
            PlaintextPayload: streamPayload));

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 20);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            validationResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => effect.PathIdentity == migratedPath);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> retransmittedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, sendEffect.Datagram);
        byte[] plaintext = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        QuicStreamFrame retransmittedStreamFrame = QuicS13RetransmissionTestSupport.AssertSingleStreamFrame(plaintext);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.True(retransmittedPacket.Key.PacketNumber > 7);
        Assert.DoesNotContain(runtime.SendRuntime.SentPackets, entry => entry.Key.PacketNumber == 7);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
        Assert.Equal(0UL, retransmittedStreamFrame.StreamId.Value);
        Assert.True(retransmittedStreamFrame.StreamData.SequenceEqual(streamData));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ValidatingANewPeerAddressResetsOldPathRecoveryState()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.10", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.11", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.NotEqual(baseline, dirty);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 20);

        QuicPathMigrationRecoverySnapshot afterReset = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(baseline, afterReset);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.False(runtime.CandidatePaths.ContainsKey(migratedPath));
        Assert.Equal(migratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.Recovery));
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }
}
