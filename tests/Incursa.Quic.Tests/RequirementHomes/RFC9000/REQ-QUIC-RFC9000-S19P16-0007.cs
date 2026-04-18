namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0007")]
public sealed class REQ_QUIC_RFC9000_S19P16_0007
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0007">Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than any previously sent to the peer MUST be treated as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0007")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void RetireConnectionIdFrame_AcceptsPreviouslyIssuedSequences()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] statelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(0x30, QuicStatelessReset.StatelessResetTokenLength);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 7UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(7UL));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            QuicS17P2P3TestSupport.PacketConnectionId,
            retirePayload,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0007">Receipt of a RETIRE_CONNECTION_ID frame containing a sequence number greater than any previously sent to the peer MUST be treated as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0007")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RetireConnectionIdFrame_RejectsSequencesGreaterThanTheHighestIssuedValue()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] statelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(0x31, QuicStatelessReset.StatelessResetTokenLength);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 7UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(8UL));
        QuicConnectionTransitionResult result = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            QuicS17P2P3TestSupport.PacketConnectionId,
            retirePayload,
            observedAtTicks: 1);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
    }
}
