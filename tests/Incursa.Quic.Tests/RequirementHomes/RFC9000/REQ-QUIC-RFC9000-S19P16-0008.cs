namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0008")]
public sealed class REQ_QUIC_RFC9000_S19P16_0008
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0008">The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination Connection ID field of the packet in which the frame is contained.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0009">The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0008")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RetireConnectionIdFrame_RejectsThePacketDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] issuedStatelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(0x30, QuicStatelessReset.StatelessResetTokenLength);
        byte[] statelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(0x40, QuicStatelessReset.StatelessResetTokenLength);
        byte[] retiredConnectionId = QuicS17P2P3TestSupport.CreateSequentialBytes(0x50, 4);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 19UL,
                StatelessResetToken: issuedStatelessResetToken),
            nowTicks: 0).StateChanged);

        byte[] newConnectionIdPayload = QuicFrameTestData.BuildNewConnectionIdFrame(
            new QuicNewConnectionIdFrame(9UL, 0UL, retiredConnectionId, statelessResetToken));
        QuicConnectionTransitionResult newConnectionIdResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            QuicS17P2P3TestSupport.PacketConnectionId,
            newConnectionIdPayload,
            observedAtTicks: 1);

        Assert.True(newConnectionIdResult.StateChanged);
        Assert.True(runtime.CurrentPeerDestinationConnectionId.Span.SequenceEqual(retiredConnectionId));

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(9UL));
        QuicConnectionTransitionResult retireResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 2);

        Assert.True(retireResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
    }
}
