namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-CRT-0070")]
public sealed class REQ_QUIC_CRT_0070
{
    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void FreshPathPromotionResetsRecoveryWhilePortOnlyPromotionRequestsStateRestore()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.60", "198.51.100.60", 443, 61234);
        QuicConnectionPathIdentity freshPath = new("203.0.113.61", "198.51.100.61", 443, 61235);
        using QuicConnectionRuntime freshRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(freshRuntime);

        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(freshRuntime);

        QuicConnectionTransitionResult freshResult = PromoteValidatedPath(freshRuntime, freshPath);
        QuicPathMigrationRecoverySnapshot afterFreshPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(freshRuntime);

        Assert.NotEqual(dirty.CongestionWindowBytes, afterFreshPromotion.CongestionWindowBytes);
        Assert.Contains(freshResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == freshPath
            && !promote.RestoreSavedState);

        QuicConnectionPathIdentity portOnlyPath = activePath with { RemotePort = 4433 };
        using QuicConnectionRuntime portOnlyRuntime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(portOnlyRuntime);
        QuicPathMigrationRecoverySnapshot beforePortOnlyPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(portOnlyRuntime);

        QuicConnectionTransitionResult portOnlyResult = PromoteValidatedPath(portOnlyRuntime, portOnlyPath);
        QuicPathMigrationRecoverySnapshot afterPortOnlyPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(portOnlyRuntime);

        Assert.Equal(beforePortOnlyPromotion.CongestionWindowBytes, afterPortOnlyPromotion.CongestionWindowBytes);
        Assert.Equal(beforePortOnlyPromotion.SmoothedRttMicros, afterPortOnlyPromotion.SmoothedRttMicros);
        Assert.Contains(portOnlyResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == portOnlyPath
            && promote.RestoreSavedState);
    }

    private static QuicConnectionTransitionResult PromoteValidatedPath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity)
    {
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(ObservedAtTicks: 20, pathIdentity, datagram),
            nowTicks: 20);

        return runtime.Transition(
            new QuicConnectionPathValidationSucceededEvent(ObservedAtTicks: 30, pathIdentity),
            nowTicks: 30);
    }
}
