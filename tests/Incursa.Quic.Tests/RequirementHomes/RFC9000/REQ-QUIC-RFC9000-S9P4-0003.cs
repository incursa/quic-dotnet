namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P4-0003")]
public sealed class REQ_QUIC_RFC9000_S9P4_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P4-0002")]
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
        Assert.Equal(afterValidationProbe.BytesInFlightBytes, afterPromotion.BytesInFlightBytes);
        Assert.Equal(afterValidationProbe.RecoveryStartTimeMicros, afterPromotion.RecoveryStartTimeMicros);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(portOnlyPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }
}
