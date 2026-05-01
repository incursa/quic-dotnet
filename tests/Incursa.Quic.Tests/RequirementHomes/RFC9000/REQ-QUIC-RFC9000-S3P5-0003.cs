namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0003">STREAM frames received after sending a STOP_SENDING frame MUST still be counted toward connection and stream flow control even if they are discarded upon receipt.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0003")]
public sealed class REQ_QUIC_RFC9000_S3P5_0003
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    private static readonly byte[] PacketSourceConnectionId =
    [
        0x21, 0x22, 0x23, 0x24,
    ];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortStreamReadsAsync_KeepsCountingSubsequentStreamFramesTowardFlowControl()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        Assert.True(TryGetStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);
        Assert.Equal(0x99UL, stopSendingFrame.ApplicationProtocolErrorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, runtime.StreamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(2UL, snapshot.AccountedBytesReceived);
        Assert.Equal(2UL, snapshot.UniqueBytesReceived);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AbortStreamReadsAsync_CountsOnlyNewOverlappingBytesAfterStopSending()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        Assert.True(TryGetStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, [0x33, 0x44, 0x55, 0x66], offset: 2),
            out QuicStreamFrame overlappingFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(overlappingFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(6UL, runtime.StreamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(6UL, snapshot.AccountedBytesReceived);
        Assert.Equal(6UL, snapshot.UniqueBytesReceived);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0003")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortStreamReadsAsync_StillEnforcesFlowControlForDiscardedStreamFrames()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        Assert.True(TryGetStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, new byte[65], offset: 0),
            out QuicStreamFrame frame));

        Assert.False(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(0UL, runtime.StreamRegistry.Bookkeeping.ConnectionAccountedBytesReceived);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot((ulong)stream.Id, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(0UL, snapshot.AccountedBytesReceived);
        Assert.Equal(0UL, snapshot.UniqueBytesReceived);
    }

    private static bool TryGetStopSendingFrame(
        QuicConnectionRuntime runtime,
        IEnumerable<QuicConnectionSendDatagramEffect> sendEffects,
        out QuicStopSendingFrame stopSendingFrame)
    {
        foreach (QuicConnectionSendDatagramEffect effect in sendEffects)
        {
            QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId, PacketSourceConnectionId);
            if (!coordinator.TryOpenProtectedApplicationDataPacket(
                effect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength))
            {
                continue;
            }

            if (QuicFrameCodec.TryParseStopSendingFrame(
                openedPacket.AsSpan(payloadOffset, payloadLength),
                out stopSendingFrame,
                out _))
            {
                return true;
            }
        }

        stopSendingFrame = default;
        return false;
    }
}
