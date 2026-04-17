namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S11P2-0001">If an application-level error affects a single stream but otherwise leaves the connection in a recoverable state, the endpoint can send a RESET_STREAM frame (Section 19.4) with an appropriate error code to terminate just the affected stream.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S11P2-0001")]
public sealed class REQ_QUIC_RFC9000_S11P2_0001
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S11P2-0001")]
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
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);

        QuicStream replacementStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.True(replacementStream.CanWrite);

        await replacementStream.DisposeAsync();
        await targetStream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S11P2-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortWrite_DoesNotSpreadToAnotherWritableStream()
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
        QuicStream unaffectedStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        targetStream.Abort(QuicAbortDirection.Write, 0x99);

        QuicException abortedWriteException = await Assert.ThrowsAsync<QuicException>(
            () => targetStream.WriteAsync(new byte[] { 0x11 }, 0, 1));
        Assert.Equal(QuicError.OperationAborted, abortedWriteException.QuicError);
        Assert.Null(abortedWriteException.ApplicationErrorCode);

        Assert.True(unaffectedStream.CanWrite);
        await unaffectedStream.WriteAsync(new byte[] { 0x22 }, 0, 1);
        Assert.Equal(QuicConnectionPhase.Active, runtime.Phase);

        await unaffectedStream.DisposeAsync();
        await targetStream.DisposeAsync();
    }
}
