namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0006")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0006
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0006">Endpoints MUST limit the use of a connection ID to packets sent from a single local address to a single destination address.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0006")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidatedMigrationUsesANewPeerConnectionIdForTheNewAddressPair()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.241", "198.51.100.241", RemotePort: 443, LocalPort: 61234);
        byte[] originalPairConnectionId = [0x71, 0x72, 0x73, 0x74];
        byte[] migratedPairConnectionId = [0x81, 0x82, 0x83, 0x84];

        await BindPeerConnectionIdToCurrentPath(runtime, originalPairConnectionId);
        QuicConnectionTransitionResult newConnectionIdResult =
            AddMigratedPathConnectionId(runtime, migratedPairConnectionId);

        Assert.Equal(originalPairConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.DoesNotContain(
            newConnectionIdResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            send => QuicPeerConnectionIdSelectionTestSupport.ApplicationDataDatagramUsesDestinationConnectionId(
                send.Datagram,
                migratedPairConnectionId));
        PromoteMigratedPath(runtime, migratedPath);

        QuicConnectionSendDatagramEffect sendAfterMigration =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(migratedPath, sendAfterMigration.PathIdentity);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            sendAfterMigration.Datagram,
            migratedPairConnectionId);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramDoesNotUseDestinationConnectionId(
            sendAfterMigration.Datagram,
            originalPairConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ValidatedMigrationWithoutAnUnusedPeerConnectionIdDoesNotReuseTheOriginalAddressPairConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity originalPath = runtime.ActivePath!.Value.Identity;
        QuicConnectionPathIdentity migratedPath = new("203.0.113.242", "198.51.100.242", RemotePort: 443, LocalPort: 61235);
        byte[] originalPairConnectionId = [0x91, 0x92, 0x93, 0x94];

        await BindPeerConnectionIdToCurrentPath(runtime, originalPairConnectionId);

        QuicConnectionTransitionResult validationResult = ValidateMigratedPath(runtime, migratedPath);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(originalPath, runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.True(candidatePath.Validation.IsValidated);
        Assert.DoesNotContain(validationResult.Effects, effect => effect is QuicConnectionPromoteActivePathEffect);

        QuicConnectionSendDatagramEffect sendAfterRejectedPromotion =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(originalPath, sendAfterRejectedPromotion.PathIdentity);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            sendAfterRejectedPromotion.Datagram,
            originalPairConnectionId);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ValidatedMigrationUsesAMaximumLengthPeerConnectionIdOnTheNewAddressPair()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.243", "198.51.100.243", RemotePort: 443, LocalPort: 61236);
        byte[] originalPairConnectionId = [0xA1, 0xA2, 0xA3, 0xA4];
        byte[] migratedPairConnectionId = Enumerable.Range(0, QuicConnectionIdKey.MaximumLength)
            .Select(value => (byte)(0xB0 + value))
            .ToArray();

        await BindPeerConnectionIdToCurrentPath(runtime, originalPairConnectionId);
        QuicConnectionTransitionResult newConnectionIdResult =
            AddMigratedPathConnectionId(runtime, migratedPairConnectionId);

        Assert.Equal(originalPairConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.DoesNotContain(
            newConnectionIdResult.Effects.OfType<QuicConnectionSendDatagramEffect>(),
            send => QuicPeerConnectionIdSelectionTestSupport.ApplicationDataDatagramUsesDestinationConnectionId(
                send.Datagram,
                migratedPairConnectionId));
        PromoteMigratedPath(runtime, migratedPath);

        QuicConnectionSendDatagramEffect sendAfterMigration =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        Assert.Equal(migratedPath, sendAfterMigration.PathIdentity);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            sendAfterMigration.Datagram,
            migratedPairConnectionId);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramDoesNotUseDestinationConnectionId(
            sendAfterMigration.Datagram,
            originalPairConnectionId);
    }

    internal static async Task BindPeerConnectionIdToCurrentPath(
        QuicConnectionRuntime runtime,
        byte[] connectionId)
    {
        QuicConnectionTransitionResult newConnectionIdResult = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 1,
            connectionId,
            observedAtTicks: 10,
            statelessResetTokenStart: 0x70);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.Equal(connectionId.ToArray(), runtime.CurrentPeerDestinationConnectionId.ToArray());

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            send.Datagram,
            connectionId.ToArray());
    }

    internal static QuicConnectionTransitionResult AddMigratedPathConnectionId(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> connectionId)
    {
        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 2,
            retirePriorTo: 1,
            connectionId,
            observedAtTicks: 12,
            statelessResetTokenStart: 0x80);

        Assert.True(result.StateChanged);
        return result;
    }

    internal static QuicConnectionTransitionResult PromoteMigratedPath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity migratedPath)
    {
        QuicConnectionTransitionResult validationResult = ValidateMigratedPath(runtime, migratedPath);

        Assert.True(validationResult.StateChanged);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(migratedPath, runtime.ActivePath!.Value.Identity);
        Assert.DoesNotContain(runtime.CandidatePaths.Keys, path => path.Equals(migratedPath));
        Assert.Contains(
            validationResult.Effects,
            effect => effect is QuicConnectionPromoteActivePathEffect promote
                && promote.PathIdentity == migratedPath);
        return validationResult;
    }

    internal static QuicConnectionTransitionResult ValidateMigratedPath(
        QuicConnectionRuntime runtime,
        QuicConnectionPathIdentity migratedPath)
    {
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
        Assert.True(runtime.CandidatePaths.TryGetValue(migratedPath, out QuicConnectionCandidatePathRecord candidatePath));
        Assert.False(candidatePath.Validation.IsValidated);

        return QuicPathMigrationRecoveryTestSupport.ValidatePath(
            runtime,
            migratedPath,
            observedAtTicks: 30);
    }
}
