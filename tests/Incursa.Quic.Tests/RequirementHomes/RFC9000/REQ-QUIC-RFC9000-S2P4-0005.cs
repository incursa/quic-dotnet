namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0005">An application protocol MAY reset a stream if the stream is not already in a terminal state, resulting in a RESET_STREAM frame.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
public sealed class REQ_QUIC_RFC9000_S2P4_0005
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortWrite_EmitsResetStreamForTheTargetStream()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream targetStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        targetStream.Abort(QuicAbortDirection.Write, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicFrameCodec.TryParseResetStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicResetStreamFrame resetStreamFrame,
            out _));
        Assert.Equal((ulong)targetStream.Id, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);
        Assert.False(targetStream.CanWrite);
        Assert.True(targetStream.CanRead);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);

        await targetStream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P4-0005")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortWrite_DoesNotEmitAnotherResetStreamAfterTheWritableSideHasClosed()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream targetStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        targetStream.Abort(QuicAbortDirection.Write, 0x99);
        Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        outboundEffects.Clear();
        targetStream.Abort(QuicAbortDirection.Write, 0x99);
        Assert.Empty(outboundEffects);
        Assert.False(targetStream.CanWrite);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);

        await targetStream.DisposeAsync();
    }
}
