namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P1-0014")]
public sealed class REQ_QUIC_RFC9000_S5P1P1_0014
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0014">After processing a NEW_CONNECTION_ID frame and adding and retiring active connection IDs, if the number of active connection IDs exceeds the value advertised in the active_connection_id_limit transport parameter, an endpoint MUST close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0014")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_ClosesWhenTheActiveConnectionIdSetExceedsTheLocalLimit()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionId: [0x10, 0x11, 0x12],
            observedAtTicks: 9,
            statelessResetTokenStart: 0x20).StateChanged);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 2UL,
            retirePriorTo: 0UL,
            connectionId: [0x20, 0x21, 0x22],
            observedAtTicks: 10,
            statelessResetTokenStart: 0x30);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.Equal(QuicTransportErrorCode.ConnectionIdLimitError, runtime.TerminalState!.Value.Close.TransportErrorCode);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0014">After processing a NEW_CONNECTION_ID frame and adding and retiring active connection IDs, if the number of active connection IDs exceeds the value advertised in the active_connection_id_limit transport parameter, an endpoint MUST close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0014")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void NewConnectionIdFrame_AllowsAReplacementWhenRetirePriorToKeepsTheActiveSetWithinTheLocalLimit()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        Assert.True(QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            retirePriorTo: 0UL,
            connectionId: [0x30, 0x31, 0x32],
            observedAtTicks: 9,
            statelessResetTokenStart: 0x40).StateChanged);

        QuicConnectionTransitionResult result = QuicConnectionIdLifecycleTestSupport.ProcessNewConnectionIdFrame(
            runtime,
            sequenceNumber: 2UL,
            retirePriorTo: 1UL,
            connectionId: [0x40, 0x41, 0x42],
            observedAtTicks: 10,
            statelessResetTokenStart: 0x50);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P1-0014">After processing a NEW_CONNECTION_ID frame and adding and retiring active connection IDs, if the number of active connection IDs exceeds the value advertised in the active_connection_id_limit transport parameter, an endpoint MUST close the connection with an error of type CONNECTION_ID_LIMIT_ERROR.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P1-0014")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void NewConnectionIdFrame_AllowsAnExactDuplicateWhenAlreadyAtTheLocalLimit()
    {
        QuicConnectionPeerConnectionIdState state = new();
        byte[] firstConnectionId = [0x50, 0x51, 0x52];
        QuicNewConnectionIdFrame frame = new(
            1UL,
            0UL,
            firstConnectionId,
            QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60));

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            frame,
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out destinationConnectionIdChanged,
            out retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.False(destinationConnectionIdChanged);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(2, state.ActiveConnectionIdCount);
    }
}
