// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0009")]
public sealed class REQ_QUIC_RFC9000_S19P16_0009
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1328">The sequence number specified in a RETIRE_CONNECTION_ID frame MUST NOT refer to the Destination Connection ID field of the packet in which the frame is contained.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0009">The peer MAY treat this as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void RetireConnectionIdFrame_TreatsThePacketDestinationConnectionIdAsAProtocolViolation()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] issuedStatelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(0x35, QuicStatelessReset.StatelessResetTokenLength);

        Assert.True(runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 10UL,
                StatelessResetToken: issuedStatelessResetToken),
            nowTicks: 0).StateChanged);

        byte[] retirePayload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(10UL));
        QuicConnectionTransitionResult retireResult = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentPeerDestinationConnectionId.Span,
            retirePayload,
            observedAtTicks: 2,
            routedLocallyIssuedConnectionId: 10UL);

        Assert.True(retireResult.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
    }
}
