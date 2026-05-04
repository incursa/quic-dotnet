namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0007")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0007
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0007">Endpoints SHOULD retire connection IDs when they are no longer actively using either the local or destination address for which the connection ID was used.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ValidatedMigrationRetiresThePeerConnectionIdBoundToTheAbandonedAddressPair()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionPathIdentity migratedPath = new("203.0.113.244", "198.51.100.244", RemotePort: 443, LocalPort: 61237);
        byte[] originalPairConnectionId = [0xC1, 0xC2, 0xC3, 0xC4];
        byte[] migratedPairConnectionId = [0xD1, 0xD2, 0xD3, 0xD4];

        await REQ_QUIC_RFC9000_S5P1P2_0006.BindPeerConnectionIdToCurrentPath(runtime, originalPairConnectionId);
        _ = REQ_QUIC_RFC9000_S5P1P2_0006.AddMigratedPathConnectionId(runtime, migratedPairConnectionId);
        Assert.Equal(originalPairConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());

        QuicConnectionTransitionResult validationResult =
            REQ_QUIC_RFC9000_S5P1P2_0006.PromoteMigratedPath(runtime, migratedPath);

        ulong[] retiredSequenceNumbers = QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(
            runtime,
            validationResult);

        Assert.Contains(1UL, retiredSequenceNumbers);
        Assert.DoesNotContain(2UL, retiredSequenceNumbers);
        Assert.Equal(migratedPairConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task SameAddressPairConnectionIdRotationDoesNotRetireTheEarlierPeerConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] firstConnectionIdForSamePair = [0xE1, 0xE2, 0xE3, 0xE4];
        byte[] secondConnectionIdForSamePair = [0xF1, 0xF2, 0xF3, 0xF4];

        await REQ_QUIC_RFC9000_S5P1P2_0006.BindPeerConnectionIdToCurrentPath(runtime, firstConnectionIdForSamePair);
        _ = REQ_QUIC_RFC9000_S5P1P2_0006.AddMigratedPathConnectionId(runtime, secondConnectionIdForSamePair);

        QuicConnectionEffect[] effects =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureEffectsAsync(runtime);
        QuicConnectionTransitionResult result = new(
            Sequence: 0,
            ObservedAtTicks: 0,
            EventKind: QuicConnectionEventKind.StreamAction,
            PreviousPhase: runtime.Phase,
            CurrentPhase: runtime.Phase,
            StateChanged: effects.Length > 0,
            Effects: effects);

        ulong[] retiredSequenceNumbers = QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(
            runtime,
            result);

        Assert.Empty(retiredSequenceNumbers);
        Assert.Single(effects.OfType<QuicConnectionSendDatagramEffect>());
    }
}
