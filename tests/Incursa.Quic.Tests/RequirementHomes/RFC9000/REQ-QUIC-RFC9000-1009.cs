namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1009")]
public sealed class REQ_QUIC_RFC9000_1009
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public void AfterProcessingOneRttPacketsTheRuntimeDoesNotEmitZeroRttPackets()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();

        byte[] protectedPacket = QuicS17P2P3TestSupport.BuildExpectedOneRttPacket(
            QuicFrameTestData.BuildPingFrame(),
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            runtime.TlsState.CurrentOneRttKeyPhase == 1);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Empty(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void BeforeOneRttProcessingTheBootstrapPathStillEmitsZeroRttPackets()
    {
        QuicDetachedResumptionTicketSnapshot detachedResumptionTicketSnapshot =
            QuicResumptionClientHelloTestSupport.CreateDetachedResumptionTicketSnapshot(ticketMaxEarlyDataSize: 4_096);
        QuicTransportParameters localTransportParameters = QuicS17P2P3TestSupport.CreateBootstrapLocalTransportParameters();
        long nowTicks = detachedResumptionTicketSnapshot.CapturedAtTicks + 1;

        using QuicConnectionRuntime clientRuntime = QuicS17P2P3TestSupport.CreateClientRuntime(detachedResumptionTicketSnapshot);

        QuicConnectionTransitionResult result = clientRuntime.Transition(
            new QuicConnectionHandshakeBootstrapRequestedEvent(
                ObservedAtTicks: nowTicks,
                LocalTransportParameters: localTransportParameters),
            nowTicks);

        Assert.Single(QuicS17P2P3TestSupport.GetInitialSendEffects(result.Effects));
        Assert.Single(QuicS17P2P3TestSupport.GetZeroRttSendEffects(result.Effects));
    }
}
