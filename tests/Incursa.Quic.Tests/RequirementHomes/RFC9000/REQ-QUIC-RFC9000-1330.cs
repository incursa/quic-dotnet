namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1330")]
public sealed class REQ_QUIC_RFC9000_1330
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1330">An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1330")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void RetireConnectionIdFrame_WhenPeerRequestedZeroLengthConnectionId_ClosesWithProtocolViolation()
    {
        using QuicConnectionRuntime runtime = CreateRuntime(ReadOnlySpan<byte>.Empty);

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicConnectionTransitionResult result = ProcessPeerRetireConnectionIdFrame(
            runtime,
            sequenceNumber: 1UL,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1330">An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1330")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void ProtectedPacketWithoutRetireConnectionIdKeepsTheConnectionOpen()
    {
        using QuicConnectionRuntime runtime = CreateRuntime(ReadOnlySpan<byte>.Empty);

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        _ = QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            QuicFrameTestData.BuildPingFrame(),
            observedAtTicks: 10);

        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Null(runtime.TerminalState);
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-1330">An endpoint that provides a zero-length connection ID MUST treat receipt of a RETIRE_CONNECTION_ID frame as a connection error of type PROTOCOL_VIOLATION.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-1330")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void RetireConnectionIdFrame_WhenPeerRequestedZeroLengthConnectionIdAndSequenceIsZero_ClosesWithProtocolViolation()
    {
        using QuicConnectionRuntime runtime = CreateRuntime(ReadOnlySpan<byte>.Empty);

        Assert.True(runtime.CurrentPeerDestinationConnectionId.IsEmpty);

        QuicConnectionTransitionResult result = ProcessPeerRetireConnectionIdFrame(
            runtime,
            sequenceNumber: 0UL,
            observedAtTicks: 10);

        Assert.True(result.StateChanged);
        Assert.Equal(QuicConnectionPhase.Closing, runtime.Phase);
        Assert.NotNull(runtime.TerminalState);
        Assert.Equal(QuicConnectionCloseOrigin.Local, runtime.TerminalState!.Value.Origin);
        Assert.Equal(QuicTransportErrorCode.ProtocolViolation, runtime.TerminalState.Value.Close.TransportErrorCode);
    }

    private static QuicConnectionRuntime CreateRuntime(ReadOnlySpan<byte> peerInitialSourceConnectionId)
    {
        QuicConnectionRuntime runtime = QuicPathMigrationRecoveryTestSupport.CreateRuntimeWithActivePath(
            new("203.0.113.210", RemotePort: 443));

        Assert.True(runtime.TrySetHandshakeDestinationConnectionId([0x71, 0x72, 0x73]));
        Assert.True(runtime.TrySetHandshakeSourceConnectionId([0x81, 0x82, 0x83, 0x84]));
        CommitLocalTransportParameters(runtime, ReadOnlySpan<byte>.Empty);

        QuicTransportParameters peerTransportParameters = QuicPostHandshakeTicketTestSupport.CreatePeerTransportParameters();
        peerTransportParameters.InitialSourceConnectionId = peerInitialSourceConnectionId.ToArray();
        peerTransportParameters.ActiveConnectionIdLimit = 3UL;

        QuicPathMigrationRecoveryTestSupport.CommitPeerTransportParametersAndSeedOneRttPacketProtectionMaterial(
            runtime,
            peerTransportParameters);

        return runtime;
    }

    private static void CommitLocalTransportParameters(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> initialSourceConnectionId)
    {
        QuicTransportParameters localTransportParameters = new()
        {
            InitialSourceConnectionId = initialSourceConnectionId.ToArray(),
        };

        Assert.True(runtime.Transition(
            new QuicConnectionTlsStateUpdatedEvent(
                ObservedAtTicks: 0,
                new QuicTlsStateUpdate(
                    QuicTlsUpdateKind.LocalTransportParametersReady,
                    TransportParameters: localTransportParameters)),
            nowTicks: 0).StateChanged);
        Assert.NotNull(runtime.TlsState.LocalTransportParameters);
        Assert.Equal(
            initialSourceConnectionId.ToArray(),
            runtime.TlsState.LocalTransportParameters!.InitialSourceConnectionId);
    }

    private static QuicConnectionTransitionResult ProcessPeerRetireConnectionIdFrame(
        QuicConnectionRuntime runtime,
        ulong sequenceNumber,
        long observedAtTicks)
    {
        byte[] payload = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(sequenceNumber));

        return QuicS19P16RetireConnectionIdTestSupport.TransitionOneRttPacket(
            runtime,
            runtime.ActivePath!.Value.Identity,
            runtime.CurrentHandshakeSourceConnectionId.Span,
            payload,
            observedAtTicks);
    }
}
