namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P5-0011")]
public sealed class REQ_QUIC_RFC9000_S9P5_0011
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConsecutiveValidatedAddressChangesEachResetPathRecoveryState()
    {
        QuicConnectionPathIdentity activePath = new("203.0.113.132", RemotePort: 443);
        QuicConnectionPathIdentity firstMigratedPath = new("203.0.113.133", RemotePort: 443);
        QuicConnectionPathIdentity secondMigratedPath = new("203.0.113.134", RemotePort: 443);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);
        QuicPathMigrationRecoverySnapshot baseline = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                firstMigratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 10).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            firstMigratedPath,
            observedAtTicks: 20).StateChanged);
        Assert.Equal(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(firstMigratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(firstMigratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 30,
                secondMigratedPath,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 30).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            secondMigratedPath,
            observedAtTicks: 40).StateChanged);
        Assert.Equal(baseline, QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime));
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(secondMigratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(secondMigratedPath.RemoteAddress, runtime.LastValidatedRemoteAddress);
    }
}
