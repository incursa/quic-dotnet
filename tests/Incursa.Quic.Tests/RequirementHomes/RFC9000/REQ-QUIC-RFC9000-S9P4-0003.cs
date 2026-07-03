// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
public sealed class REQ_QUIC_RFC9000_S9P4_0003
{
    [Fact]
    [Requirement("RFC9000-S9-4-P2-S1-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PortOnlyPathPromotionRetainsCongestionControlState()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.30", RemotePort: 443);
        QuicConnectionPathIdentity portOnlyPath = new("203.0.113.30", RemotePort: 8443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                portOnlyPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10).StateChanged);
        QuicPathMigrationRecoverySnapshot afterValidationProbe =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            portOnlyPath,
            observedAtTicks: 20);

        QuicPathMigrationRecoverySnapshot afterPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(afterValidationProbe.CongestionWindowBytes, afterPromotion.CongestionWindowBytes);
        Assert.Equal(afterValidationProbe.SlowStartThresholdBytes, afterPromotion.SlowStartThresholdBytes);
        Assert.Equal(afterValidationProbe.SmoothedRttMicros, afterPromotion.SmoothedRttMicros);
        Assert.Equal(afterValidationProbe.RttVarMicros, afterPromotion.RttVarMicros);
        Assert.Equal(afterValidationProbe.BytesInFlightBytes, afterPromotion.BytesInFlightBytes);
        Assert.Equal(afterValidationProbe.SentPacketCount, afterPromotion.SentPacketCount);
        Assert.Equal(afterValidationProbe.PendingRetransmissionCount, afterPromotion.PendingRetransmissionCount);
        Assert.Equal(afterValidationProbe.HasAckElicitingPacketsInFlight, afterPromotion.HasAckElicitingPacketsInFlight);
        Assert.Equal(afterValidationProbe.LossDetectionDeadlineMicros, afterPromotion.LossDetectionDeadlineMicros);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(portOnlyPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PortOnlyPathPromotionKeepsOutstandingStreamDataTrackedWithoutImmediateRetransmission()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.30", RemotePort: 443);
        QuicConnectionPathIdentity portOnlyPath = new("203.0.113.30", RemotePort: 8443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        byte[] streamData = [0x61, 0x62, 0x63];
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

        QuicPathMigrationRecoverySnapshot beforeRebind = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                portOnlyPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            portOnlyPath,
            observedAtTicks: 20);

        QuicPathMigrationRecoverySnapshot afterRebind = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.True(validationResult.StateChanged);
        Assert.Equal(beforeRebind.CongestionWindowBytes, afterRebind.CongestionWindowBytes);
        Assert.Equal(beforeRebind.SmoothedRttMicros, afterRebind.SmoothedRttMicros);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(portOnlyPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(runtime.SendRuntime.SentPackets, entry => entry.Key.PacketNumber == 7);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.DoesNotContain(
            validationResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            effect => effect.PathIdentity == portOnlyPath);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }
}
