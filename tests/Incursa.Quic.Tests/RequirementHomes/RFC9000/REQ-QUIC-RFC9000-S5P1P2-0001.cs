namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0001")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0001">An endpoint MAY change the connection ID it uses for a peer to another available one at any time during the connection.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task NewConnectionIdFrame_SwitchesOutboundPeerDestinationConnectionIdDuringTheConnection()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] originalDestinationConnectionId = runtime.CurrentPeerDestinationConnectionId.ToArray();
        byte[] switchedDestinationConnectionId = [0x51, 0x52, 0x53, 0x54];

        QuicConnectionTransitionResult newConnectionIdResult = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1,
            retirePriorTo: 0,
            switchedDestinationConnectionId,
            observedAtTicks: 10,
            statelessResetTokenStart: 0x90);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.Equal(switchedDestinationConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.NotEqual(originalDestinationConnectionId, runtime.CurrentPeerDestinationConnectionId.ToArray());

        QuicConnectionSendDatagramEffect send =
            await QuicPeerConnectionIdSelectionTestSupport.OpenOutboundStreamAndCaptureSingleSendAsync(runtime);

        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramOpensWithDestination(
            runtime,
            send.Datagram,
            switchedDestinationConnectionId);
        QuicPeerConnectionIdSelectionTestSupport.AssertApplicationDataDatagramDoesNotOpenWithDestination(
            runtime,
            send.Datagram,
            originalDestinationConnectionId);
    }
}
