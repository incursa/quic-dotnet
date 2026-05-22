namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0726">All frames MAY appear in 1-RTT packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0726")]
public sealed class REQ_QUIC_RFC9000_0726
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ApplicationDataPacketReceived_AllowsRepresentativeControlAndStreamFramesInAOneRttPacket()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        byte[] applicationPayload =
        [
            .. QuicFrameTestData.BuildPingFrame(),
            .. QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 1, [0x11, 0x22], offset: 0),
            .. QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame([0x33, 0x44])),
            .. QuicFrameTestData.BuildHandshakeDoneFrame(),
        ];

        QuicTlsPacketProtectionMaterial material = runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value;
        byte[] protectedPacket = QuicS17P3P1TestSupport.CreateProtectedApplicationDataPacket(
            runtime.CurrentPeerDestinationConnectionId.Span,
            [0x00, 0x00, 0x00, 0x01],
            applicationPayload,
            material,
            declaredPacketNumberLength: 4);

        Assert.True(QuicPacketParser.TryGetPacketNumberSpace(protectedPacket, out QuicPacketNumberSpace packetNumberSpace));
        Assert.Equal(QuicPacketNumberSpace.ApplicationData, packetNumberSpace);

        QuicConnectionTransitionResult result = runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 10,
                runtime.ActivePath!.Value.Identity,
                protectedPacket),
            nowTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }
}
