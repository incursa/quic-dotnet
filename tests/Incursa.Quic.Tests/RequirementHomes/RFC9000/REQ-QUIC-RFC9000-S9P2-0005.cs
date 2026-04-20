namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P2-0005")]
public sealed class REQ_QUIC_RFC9000_S9P2_0005
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratingToANewLocalAddressReenablesEcnValidationOnTheNewPath()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.70",
            LocalAddress: "198.51.100.70",
            RemotePort: 443,
            LocalPort: 61294);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.70",
            LocalAddress: "198.51.100.71",
            RemotePort: 443,
            LocalPort: 61295);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicPathMigrationRecoveryTestSupport.DirtyRecoveryState(runtime);
        QuicPathMigrationRecoverySnapshot dirty = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.False(dirty.EcnValidated);

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

        QuicPathMigrationRecoverySnapshot afterPromotion = QuicPathMigrationRecoveryTestSupport.CaptureRecoveryState(runtime);

        Assert.True(afterPromotion.EcnValidated);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void MigratingToANewLocalAddressResetsPriorEcnValidationCountsBeforeRevalidatingTheNewPath()
    {
        QuicConnectionPathIdentity activePath = new(
            RemoteAddress: "203.0.113.71",
            LocalAddress: "198.51.100.72",
            RemotePort: 443,
            LocalPort: 61296);
        QuicConnectionPathIdentity migratedPath = new(
            RemoteAddress: "203.0.113.71",
            LocalAddress: "198.51.100.73",
            RemotePort: 443,
            LocalPort: 61297);
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(activePath);

        QuicEcnValidationState oldPathEcnState = runtime.SendRuntime.EcnValidationState;
        oldPathEcnState.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

        Assert.True(oldPathEcnState.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out bool validationFailed));
        Assert.False(validationFailed);

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

        QuicEcnValidationState newPathEcnState = runtime.SendRuntime.EcnValidationState;
        newPathEcnState.RecordPacketSent(QuicPacketNumberSpace.ApplicationData, QuicEcnMarking.Ect0);

        Assert.True(newPathEcnState.IsEcnEnabled);
        Assert.True(newPathEcnState.TryValidateAcknowledgedEcnCounts(
            QuicPacketNumberSpace.ApplicationData,
            new QuicEcnCounts(1, 0, 0),
            newlyAcknowledgedEct0Packets: 1,
            newlyAcknowledgedEct1Packets: 0,
            largestAcknowledgedPacketNumberIncreased: true,
            out validationFailed));
        Assert.False(validationFailed);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(validationResult.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == migratedPath
            && !promote.RestoreSavedState);
    }
}
