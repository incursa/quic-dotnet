namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S5P1P2-0011")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0011
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0011">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void NewConnectionIdFrame_WithIncreasedRetirePriorToRetiresLowerSequencesBeforeUsingTheNewConnectionId()
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
            retirePriorTo: 1UL,
            connectionId: [0x20, 0x21, 0x22],
            observedAtTicks: 10,
            statelessResetTokenStart: 0x30);

        Assert.True(result.StateChanged);
        Assert.Equal([0UL], QuicConnectionIdLifecycleTestSupport.GetRetiredSequenceNumbers(runtime, result));
        Assert.Equal([0x20, 0x21, 0x22], runtime.CurrentPeerDestinationConnectionId.ToArray());
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0011">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcceptNewConnectionId_WithoutAnIncreasedRetirePriorToKeepsEarlierPeerConnectionIdsActive()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                [0x30, 0x31, 0x32],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x40)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out _,
            out ulong[] retiredSequenceNumbers));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                0UL,
                [0x40, 0x41, 0x42],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x50)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 3UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out _,
            out retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.Empty(retiredSequenceNumbers);
        Assert.Equal(3, state.ActiveConnectionIdCount);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0011">Upon receipt of an increased Retire Prior To field, the peer MUST stop using the corresponding connection IDs and retire them with RETIRE_CONNECTION_ID frames before adding the newly provided connection ID to the set of active connection IDs.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S5P1P2-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryAcceptNewConnectionId_WithRetirePriorToEqualToSequenceRetiresAllLowerSequencesBeforeAddingTheNewConnectionId()
    {
        QuicConnectionPeerConnectionIdState state = new();

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                1UL,
                0UL,
                [0x50, 0x51, 0x52],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x60)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out QuicTransportErrorCode errorCode,
            out _,
            out _));
        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);

        Assert.True(state.TryAcceptNewConnectionId(
            new QuicNewConnectionIdFrame(
                2UL,
                2UL,
                [0x60, 0x61, 0x62],
                QuicConnectionIdLifecycleTestSupport.CreateStatelessResetToken(0x70)),
            requiresZeroLengthDestinationConnectionId: false,
            activeConnectionIdLimit: 2UL,
            initialDestinationConnectionId: [0x01, 0x02, 0x03],
            out errorCode,
            out bool destinationConnectionIdChanged,
            out ulong[] retiredSequenceNumbers));

        Assert.Equal(QuicTransportErrorCode.NoError, errorCode);
        Assert.True(destinationConnectionIdChanged);
        Assert.Equal([0UL, 1UL], retiredSequenceNumbers.Order().ToArray());
        Assert.Equal(1, state.ActiveConnectionIdCount);
        Assert.Equal(2UL, state.CurrentDestinationConnectionIdSequence);
        Assert.Equal([0x60, 0x61, 0x62], state.CurrentDestinationConnectionId.ToArray());
    }
}
