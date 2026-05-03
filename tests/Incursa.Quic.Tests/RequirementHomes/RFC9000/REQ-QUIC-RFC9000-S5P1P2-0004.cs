namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual trace slice">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S5P1P2-0004">When the endpoint wishes to remove a connection ID from use, it MUST send a RETIRE_CONNECTION_ID frame to its peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S5P1P2-0004")]
public sealed class REQ_QUIC_RFC9000_S5P1P2_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void ConnectionIdRetiredEvent_SendsRetireConnectionIdFrameForTheRetiredSequenceNumber()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        byte[] statelessResetToken = QuicS17P2P3TestSupport.CreateSequentialBytes(
            0x90,
            QuicStatelessReset.StatelessResetTokenLength);

        QuicConnectionTransitionResult issued = runtime.Transition(
            new QuicConnectionConnectionIdIssuedEvent(
                ObservedAtTicks: 0,
                ConnectionId: 281UL,
                StatelessResetToken: statelessResetToken),
            nowTicks: 0);
        Assert.True(issued.StateChanged);

        QuicConnectionTransitionResult retired = runtime.Transition(
            new QuicConnectionConnectionIdRetiredEvent(
                ObservedAtTicks: 1,
                ConnectionId: 281UL),
            nowTicks: 1);

        Assert.True(retired.StateChanged);
        QuicConnectionSendDatagramEffect sendEffect =
            Assert.Single(retired.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Contains(
            retired.Effects,
            effect => effect is QuicConnectionRetireStatelessResetTokenEffect retire
                && retire.ConnectionId == 281UL);

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
        Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(
            payload,
            out QuicRetireConnectionIdFrame parsed,
            out int bytesConsumed));
        Assert.Equal(281UL, parsed.SequenceNumber);
        Assert.True(bytesConsumed > 0);
    }
}
