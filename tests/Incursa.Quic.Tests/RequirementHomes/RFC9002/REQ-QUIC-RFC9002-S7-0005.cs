namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9002-S7-0005">The congestion controller MUST be per path, so packets sent on other paths do not alter the current path's congestion controller.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9002-S7-0005")]
public sealed class REQ_QUIC_RFC9002_S7_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    public void CandidatePathValidationProbeDoesNotAlterTheActivePathCongestionController()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.40", RemotePort: 443);
        QuicConnectionPathIdentity candidatePath = new("203.0.113.41", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot beforeCandidateProbe =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                candidatePath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);

        QuicPathMigrationRecoverySnapshot afterCandidateProbe =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);
        Assert.True(result.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(activePath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(beforeCandidateProbe.CongestionWindowBytes, afterCandidateProbe.CongestionWindowBytes);
        Assert.Equal(beforeCandidateProbe.SlowStartThresholdBytes, afterCandidateProbe.SlowStartThresholdBytes);
        Assert.Equal(beforeCandidateProbe.BytesInFlightBytes, afterCandidateProbe.BytesInFlightBytes);
        Assert.Equal(beforeCandidateProbe.RecoveryStartTimeMicros, afterCandidateProbe.RecoveryStartTimeMicros);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionSendDatagramEffect send
            && send.PathIdentity == candidatePath
            && QuicFrameCodec.TryParsePathChallengeFrame(send.Datagram.Span, out _, out _));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    public void ValidatedPeerAddressMigrationStartsTheNewPathWithFreshCongestionState()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.42", RemotePort: 443);
        QuicConnectionPathIdentity migratedPath = new("203.0.113.43", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);
        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 20).StateChanged);

        QuicPathMigrationRecoverySnapshot afterMigration =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);
        Assert.Equal(baseline.CongestionWindowBytes, afterMigration.CongestionWindowBytes);
        Assert.Equal(baseline.SlowStartThresholdBytes, afterMigration.SlowStartThresholdBytes);
        Assert.Equal(baseline.BytesInFlightBytes, afterMigration.BytesInFlightBytes);
        Assert.Equal(baseline.RecoveryStartTimeMicros, afterMigration.RecoveryStartTimeMicros);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ActivePathLossStillUpdatesTheCurrentPathCongestionController()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.44", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        ulong initialCongestionWindowBytes =
            runtime.SendRuntime.FlowController.CongestionControlState.CongestionWindowBytes;

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 1,
            PayloadBytes: 1_200,
            SentAtMicros: 1_000,
            AckEliciting: true));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber: 1,
            scheduleRetransmission: false));

        QuicCongestionControlState congestionControlState =
            runtime.SendRuntime.FlowController.CongestionControlState;
        Assert.True(congestionControlState.HasRecoveryStartTime);
        Assert.True(congestionControlState.CongestionWindowBytes < initialCongestionWindowBytes);
    }
}
