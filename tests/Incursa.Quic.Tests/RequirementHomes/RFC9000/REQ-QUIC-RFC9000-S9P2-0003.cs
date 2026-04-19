namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P2-0003")]
public sealed class REQ_QUIC_RFC9000_S9P2_0003
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratingToANewLocalAddressRecomputesTheCongestionWindowFromTheNewPathDatagramSize()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.51",
            LocalAddress: "198.51.100.51",
            RemotePort: 443,
            LocalPort: 61276);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.51",
            LocalAddress: "198.51.100.52",
            RemotePort: 443,
            LocalPort: 61277);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        Assert.True(runtime.TrySetActivePathMaximumDatagramSize(1_400));
        runtime.SendRuntime.FlowController.CongestionControlState.UpdateMaxDatagramSize(
            1_400,
            resetToInitialWindow: true);

        ulong oldPathInitialCongestionWindowBytes = QuicCongestionControlState.ComputeInitialCongestionWindowBytes(1_400);
        ulong newPathInitialCongestionWindowBytes = QuicCongestionControlState.ComputeInitialCongestionWindowBytes(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes);

        Assert.NotEqual(oldPathInitialCongestionWindowBytes, newPathInitialCongestionWindowBytes);
        Assert.Equal(oldPathInitialCongestionWindowBytes, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime).CongestionWindowBytes);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        QuicPathMigrationRecoverySnapshot afterReset = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(newPathInitialCongestionWindowBytes, afterReset.CongestionWindowBytes);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes, runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        Assert.Equal(
            QuicConnectionPathMaximumDatagramSizeState.MinimumAllowedMaximumDatagramSizeBytes,
            runtime.SendRuntime.FlowController.CongestionControlState.MaxDatagramSizeBytes);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratingToANewLocalAddressResetsThePathRecoveryState()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.50",
            LocalAddress: "198.51.100.50",
            RemotePort: 443,
            LocalPort: 61274);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.50",
            LocalAddress: "198.51.100.51",
            RemotePort: 443,
            LocalPort: 61275);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.NotEqual(baseline, dirty);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 20).StateChanged);

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        QuicPathMigrationRecoverySnapshot afterReset = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.Equal(baseline, afterReset);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }
}
