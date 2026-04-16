namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S9P4-0007">A sender MAY make exceptions for probe packets so their loss detection is independent and does not unduly cause the congestion controller to reduce its sending rate.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S9P4-0007")]
public sealed class REQ_QUIC_RFC9000_S9P4_0007
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ProbePacketLossLeavesRecoveryStateUnchangedAtThePathValidationBoundary()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.50", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot beforeProbeLoss = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 1_300,
            AckEliciting: true,
            Retransmittable: false,
            ProbePacket: true));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            9,
            handshakeConfirmed: false));

        QuicPathMigrationRecoverySnapshot afterProbeLoss = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(beforeProbeLoss, afterProbeLoss);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NonProbePacketLossStillReducesCongestionAtTheSameBoundary()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.51", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 9,
            PayloadBytes: 1_200,
            SentAtMicros: 1_300,
            AckEliciting: true,
            Retransmittable: false));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            9,
            handshakeConfirmed: false));

        QuicPathMigrationRecoverySnapshot afterLoss = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(1_200UL, afterLoss.BytesInFlightBytes);
        Assert.Equal(3_000UL, afterLoss.CongestionWindowBytes);
        Assert.Equal(3_000UL, afterLoss.SlowStartThresholdBytes);
        Assert.Equal(1_300UL, afterLoss.RecoveryStartTimeMicros);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void IsolatedProbePacketLossDoesNotReduceTheCongestionWindow()
    {
        QuicCongestionControlState state = new();
        ulong initialCongestionWindowBytes = state.CongestionWindowBytes;
        ulong initialSlowStartThresholdBytes = state.SlowStartThresholdBytes;

        state.RegisterPacketSent(
            sentBytes: 1_200,
            isProbePacket: true);

        Assert.True(state.TryRegisterLoss(
            sentBytes: 1_200,
            sentAtMicros: 1_300,
            packetInFlight: true,
            isProbePacket: true));

        Assert.Equal(0UL, state.BytesInFlightBytes);
        Assert.Equal(initialCongestionWindowBytes, state.CongestionWindowBytes);
        Assert.Equal(initialSlowStartThresholdBytes, state.SlowStartThresholdBytes);
        Assert.Null(state.RecoveryStartTimeMicros);
    }
}
