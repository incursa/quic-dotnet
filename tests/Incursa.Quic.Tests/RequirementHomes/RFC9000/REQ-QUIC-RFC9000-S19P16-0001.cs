namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P16-0001")]
public sealed class REQ_QUIC_RFC9000_S19P16_0001
{
    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0001">An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to indicate that it will no longer use a connection ID that was issued by its peer.</workbench-requirement>
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0002">This MUST include the connection ID provided during the handshake.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0001")]
    [Requirement("REQ-QUIC-RFC9000-S19P16-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    public void ConnectionIdRetiredEvent_SendsARetireConnectionIdFrameForTheRetiredSequenceNumber()
    {
        using QuicConnectionRuntimeEndpoint endpoint = new(2);
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        QuicConnectionHandle handle = endpoint.AllocateConnectionHandle();
        QuicConnectionPathIdentity activePath = runtime.ActivePath!.Value.Identity;
        byte[] statelessResetToken = CreateStatelessResetToken(0x90);

        Assert.True(endpoint.TryRegisterConnection(handle, runtime));
        Assert.True(endpoint.TryUpdateEndpointBinding(handle, activePath));

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 281UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0);

        Assert.Contains(issued.Effects, effect => effect is QuicConnectionRegisterStatelessResetTokenEffect register && register.ConnectionId == 281UL);
        foreach (QuicConnectionEffect effect in issued.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 281UL),
            nowTicks: 1);

        Assert.True(retired.StateChanged);
        Assert.Contains(retired.Effects, effect => effect is QuicConnectionSendDatagramEffect);
        Assert.Contains(retired.Effects, effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire && retire.ConnectionId == 281UL);

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
        Assert.Equal(281UL, parsed.SequenceNumber);
        Assert.True(bytesConsumed > 0);

        foreach (QuicConnectionEffect effect in retired.Effects)
        {
            Assert.True(endpoint.TryApplyEffect(handle, effect));
        }
    }

    [Fact]
    /// <workbench-requirements generated="true" source="manual">
    ///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S19P16-0001">An endpoint sends a RETIRE_CONNECTION_ID frame (type=0x19) to indicate that it will no longer use a connection ID that was issued by its peer.</workbench-requirement>
    /// </workbench-requirements>
    [Requirement("REQ-QUIC-RFC9000-S19P16-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    public void ConnectionIdRetiredEvent_RejectsUnknownConnectionIdsWithoutSendingAFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 281UL),
            nowTicks: 1);

        Assert.False(retired.StateChanged);
        Assert.Empty(retired.Effects);
    }

    private static byte[] CreateStatelessResetToken(byte startValue)
    {
        byte[] token = new byte[QuicStatelessReset.StatelessResetTokenLength];
        for (int index = 0; index < token.Length; index++)
        {
            token[index] = unchecked((byte)(startValue + index));
        }

        return token;
    }
}
