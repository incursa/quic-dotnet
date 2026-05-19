namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0002")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0002">An endpoint MAY consume connection IDs in response to a migrating peer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidatedMigratedPath_UsesTheConsumedPeerConnectionIdForOutboundPackets()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity migratedPath = new("203.0.113.231", "198.51.100.231", 443, 61234);
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] consumedDestinationConnectionId = [0x61, 0x62, 0x63, 0x64];

        QuicConnectionTransitionResult newConnectionIdResult = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 0,
            consumedDestinationConnectionId,
            observedAtTicks: 10,
            statelessResetTokenStart: 0xA0);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.Equal(originalDestinationConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());

        byte[] migrationPacket = QuicConnectionIdLifecycleTestSupport.BuildOneRttPacket(
            runtime,
            runtime.CurrentPeerDestinationConnectionId.Span,
            QuicFrameTestData.BuildPingFrame());

        QuicConnectionTransitionResult migrationResult = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 20,
                migratedPath,
                migrationPacket),
            nowTicks: 20);

        Assert.True(migrationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(
            migratedPath,
            out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);
        Assert.Contains(
            migrationResult.Effects,
            effect => effect is QuicConnectionSendDatagramEffect send
                && send.PathIdentity == migratedPath
                && QuicS8P2PathValidationTestSupport.TryOpenPathChallengePayload(
                    runtime,
                    send.Datagram.Span,
                    out _,
                    out _,
                    out _));

        QuicConnectionTransitionResult validationResult = QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.Equal(consumedDestinationConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());

        QuicConnectionSendDatagramEffect sendAfterMigration =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(migratedPath, sendAfterMigration.PathIdentity);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            sendAfterMigration.Datagram,
            consumedDestinationConnectionId);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramDoesNotOpenWithDestination(
            runtime,
            sendAfterMigration.Datagram,
            originalDestinationConnectionId);
    }
}
