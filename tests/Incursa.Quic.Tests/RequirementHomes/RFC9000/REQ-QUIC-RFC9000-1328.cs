// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1328")]
public sealed class REQ_QUIC_RFC9000_1328
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1328">The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination Connection ID field of the packet in which the frame is contained.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0009">The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1328")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RetireConnectionIdFrame_RejectsThePacketDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithIssuedConnectionId(9UL, 0x30);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(9UL));
        QuicConnectionTransitionResult retireResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 2,
            routedLocallyIssuedConnectionId: 9UL);

        Assert.True(retireResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1328">The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination Connection ID field of the packet in which the frame is contained.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1328")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetireConnectionIdFrame_AcceptsASequenceNumberThatDiffersFromThePacketDestinationConnectionId()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithIssuedConnectionId(19UL, 0x31);
        IssueConnectionId(runtime, 20UL, 0x41);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(19UL));
        QuicConnectionTransitionResult retireResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 2,
            routedLocallyIssuedConnectionId: 20UL);

        Assert.True(retireResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1328">The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination Connection ID field of the packet in which the frame is contained.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1328")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RetireConnectionIdFrame_AllowsTheLowestSequenceNumberWhenThePacketDestinationConnectionIdDiffers()
    {
        using QuicConnectionRuntime runtime = CreateRuntimeWithIssuedConnectionId(19UL, 0x32);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(0UL));
        QuicConnectionTransitionResult retireResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 2,
            routedLocallyIssuedConnectionId: 19UL);

        Assert.True(retireResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1328")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void RetireConnectionIdFrame_FuzzAcceptsSequenceNumbersThatDifferFromPacketDestinationConnectionId()
    {
        for (ulong retiredSequenceNumber = 30; retiredSequenceNumber < 34; retiredSequenceNumber++)
        {
            ulong routedSequenceNumber = retiredSequenceNumber + 10;
            using QuicConnectionRuntime runtime = CreateRuntimeWithIssuedConnectionId(retiredSequenceNumber, 0x40);
            IssueConnectionId(runtime, routedSequenceNumber, 0x50);

            byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(retiredSequenceNumber));
            QuicConnectionTransitionResult retireResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
                runtime,
                runtime.ActivePath!.Value.Identity,
                runtime.CurrentPeerDestinationConnectionId.Span,
                retirePayload,
                observedAtTicks: (long)retiredSequenceNumber,
                routedLocallyIssuedConnectionId: routedSequenceNumber);

            Assert.True(retireResult.StateChanged);
            Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        }
    }

    private static QuicConnectionRuntime CreateRuntimeWithIssuedConnectionId(ulong connectionId, byte statelessResetTokenStart)
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport
            .CreateFinishedClientRuntimeWithValidatedActivePath(peerActiveConnectionIdLimit: 3);

        IssueConnectionId(runtime, connectionId, statelessResetTokenStart);

        return runtime;
    }

    private static void IssueConnectionId(
        QuicConnectionRuntime runtime,
        ulong connectionId,
        byte statelessResetTokenStart)
    {
        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: connectionId,
                StatelessResetToken: QuicS17P2P3TestSupport.CreateSequentialBytes(
                    statelessResetTokenStart,
                    QuicStatelessReset.StatelessResetTokenLength)),
            nowTicks: 0).StateChanged);
    }
}
