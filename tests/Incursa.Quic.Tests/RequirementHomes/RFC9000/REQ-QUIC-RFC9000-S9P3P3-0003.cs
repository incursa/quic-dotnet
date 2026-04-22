namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S9P3P3-0003")]
public sealed class REQ_QUIC_RFC9000_S9P3P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void AProtectedNonProbingPacketOnTheOriginalPathMovesTheConnectionBack()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity migratedPath = new("203.0.113.12", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord migratedCandidatePath));
        Assert.False(migratedCandidatePath.Validation.IsValidated);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, migratedPath, observedAtTicks: 21).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);

        Assert.True(SendProtectedApplicationPingPacket(
            runtime,
            migratedPath,
            [0x00, 0x00, 0x01, 0x00],
            observedAtTicks: 25).StateChanged);

        QuicConnectionTransitionResult result = SendProtectedApplicationPingPacket(
            runtime,
            originalPath,
            [0x00, 0x00, 0x01, 0x01],
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.Contains(result.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == originalPath
            && !promote.RestoreSavedState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void AnOriginalPathPacketThatDoesNotExceedTheHighestObservedPacketNumberDoesNotNeedToTriggerAReturn()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity migratedPath = new("203.0.113.13", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, migratedPath, observedAtTicks: 21).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);

        SendProtectedApplicationPingPacket(runtime, migratedPath, [0x00, 0x00, 0x01, 0x00], observedAtTicks: 25);

        QuicConnectionTransitionResult result = SendProtectedApplicationPingPacket(
            runtime,
            originalPath,
            [0x00, 0x00, 0x00, 0xFF],
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == originalPath);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S9P3P3-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void AnOriginalPathPacketAtTheHighestObservedPacketNumberDoesNotCreateANewReturnTrigger()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        Assert.True(runtime.ActivePath.HasValue);

        QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity migratedPath = new("203.0.113.14", RemotePort: 443);
        byte[] datagram = new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize];

        Assert.True(runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                datagram),
            nowTicks: 20).StateChanged);

        Assert.True(QuicPathMigrationRecoveryTestSupport.ValidatePath(runtime, migratedPath, observedAtTicks: 21).StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);

        SendProtectedApplicationPingPacket(runtime, migratedPath, [0x00, 0x00, 0x01, 0x00], observedAtTicks: 25);

        QuicConnectionTransitionResult result = SendProtectedApplicationPingPacket(
            runtime,
            originalPath,
            [0x00, 0x00, 0x01, 0x00],
            observedAtTicks: 30);

        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(result.Effects, effect =>
            effect is QuicConnectionPromoteActivePathEffect promote
            && promote.PathIdentity == originalPath);
    }

    private static QuicConnectionTransitionResult SendProtectedApplicationPingPacket(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity pathIdentity,
        byte[] packetNumberBytes,
        long observedAtTicks)
    {
        Assert.True(runtime.TlsState.OneRttOpenPacketProtectionMaterial.HasValue);
        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial.Value;

        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            packetNumberBytes,
            QuicFrameTestData.BuildPingFrame(),
            material,
            declaredPacketNumberLength: packetNumberBytes.Length);

        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: observedAtTicks,
                pathIdentity,
                protectedPacket),
            nowTicks: observedAtTicks);
    }
}
