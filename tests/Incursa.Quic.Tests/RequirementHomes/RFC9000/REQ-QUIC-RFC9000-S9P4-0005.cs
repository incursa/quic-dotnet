// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0005")]
public sealed class REQ_QUIC_RFC9000_S9P4_0005
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void PortOnlyPathPromotionRetainsRttCongestionStateAndOutstandingPackets()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.40", RemotePort: 443);
        QuicConnectionPathIdentity portOnlyPath = new("203.0.113.40", RemotePort: 8443);
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
        Assert.Equal(afterValidationProbe.ProbeTimeoutCount, afterPromotion.ProbeTimeoutCount);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(portOnlyPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void PortOnlyPeerAddressChangesKeepCongestionRttAndOutstandingPacketState()
    {
        AssertPortOnlyPathPromotionKeepsCongestionRttAndOutstandingPackets(
            new QuicConnectionPathIdentity("203.0.113.40", RemotePort: 443),
            new QuicConnectionPathIdentity("203.0.113.40", RemotePort: 8443));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P5-0006")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0004")]
    [Requirement("REQ-QUIC-RFC9000-S9P2-0005")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0005")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void PortOnlyPeerAddressChangesAtTheMaximumPortBoundaryKeepCongestionRttAndOutstandingPacketState()
    {
        AssertPortOnlyPathPromotionKeepsCongestionRttAndOutstandingPackets(
            new QuicConnectionPathIdentity("203.0.113.41", RemotePort: 443),
            new QuicConnectionPathIdentity("203.0.113.41", RemotePort: ushort.MaxValue));
    }

    private static void AssertPortOnlyPathPromotionKeepsCongestionRttAndOutstandingPackets(
        QuicConnectionPathIdentity activePath,
        QuicConnectionPathIdentity portOnlyPath)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithConfirmedHandshakeAndActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                portOnlyPath,
                datagram),
            nowTicks: 20).StateChanged);
        QuicPathMigrationRecoverySnapshot afterValidationProbe =
            QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            portOnlyPath,
            observedAtTicks: 30);
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
}
