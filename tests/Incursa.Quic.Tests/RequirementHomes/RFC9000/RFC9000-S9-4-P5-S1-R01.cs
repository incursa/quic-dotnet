// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S9-4-P5-S1-R01">A sender MAY make exceptions for probe packets so their loss detection is independent and does not unduly cause the congestion controller to reduce its sending rate.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S9-4-P5-S1-R01")]
public sealed class RFC9000_S9_4_P5_S1_R01
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
    /// <workbench-requirements generated="true" source="workbench quality sync">
    ///   <workbench-requirement requirementId="RFC9000-S9-4-P5-S1-R01">A sender MAY make exceptions for probe packets so their loss detection is independent and does not unduly cause the congestion controller to reduce its sending rate.</workbench-requirement>
    ///   <workbench-requirement requirementId="RFC9000-S14-4-P2-S2-R01">Loss of a QUIC packet that is carried in a PMTU probe SHOULD NOT trigger a congestion control reaction.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("RFC9000-S14-4-P2-S2-R01")]
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

    [Fact]
    [Requirement("RFC9000-S14-4-P2-S2-R01")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ProbePacketLossDoesNotReduceCongestionAcrossPacketSizes()
    {
        (ulong SentBytes, ulong SentAtMicros)[] cases =
        [
            (1UL, 1_000UL),
            (64UL, 1_100UL),
            (1_200UL, 1_300UL),
            (1_472UL, 1_500UL),
        ];

        foreach ((ulong sentBytes, ulong sentAtMicros) in cases)
        {
            QuicCongestionControlState state = new();
            ulong initialCongestionWindowBytes = state.CongestionWindowBytes;
            ulong initialSlowStartThresholdBytes = state.SlowStartThresholdBytes;

            state.RegisterPacketSent(
                sentBytes,
                isProbePacket: true);

            Assert.True(state.TryRegisterLoss(
                sentBytes,
                sentAtMicros,
                packetInFlight: true,
                isProbePacket: true));

            Assert.Equal(0UL, state.BytesInFlightBytes);
            Assert.Equal(initialCongestionWindowBytes, state.CongestionWindowBytes);
            Assert.Equal(initialSlowStartThresholdBytes, state.SlowStartThresholdBytes);
            Assert.Null(state.RecoveryStartTimeMicros);
        }
    }
}
