namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0002")]
public sealed class REQ_QUIC_RFC9000_S19P16_0002
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0002">This MUST include the connection ID provided during the handshake.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ConnectionIdRetiredEvent_UsesTheHandshakeConnectionIdInTheRetireFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] statelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(0x90, QuicStatelessReset.StatelessResetTokenLength);

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 0UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0);

        Assert.True(issued.StateChanged);
        Assert.Contains(issued.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 0UL);

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 0UL),
            nowTicks: 1);

        Assert.True(retired.StateChanged);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);
        Assert.Contains(retired.Effects, effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire && retire.ConnectionId == 0UL);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(retired.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True(runtime.TlsState.OneRttProtectPacketProtectionMaterial.HasValue);

        QuicHandshakeFlowCoordinator coordinator = QuicS17P2P3TestSupport.CreatePacketCoordinator();
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(payload, out QuicRetireConnectionIdFrame parsed, out int bytesConsumed));
        Assert.Equal(0UL, parsed.SequenceNumber);
        Assert.True(bytesConsumed > 0);
    }
}
