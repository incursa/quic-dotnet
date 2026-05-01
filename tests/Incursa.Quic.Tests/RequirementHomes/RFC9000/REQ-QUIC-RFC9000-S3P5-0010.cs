namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P5-0010">STOP_SENDING SHOULD only be sent for a stream that has not been reset by the peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P5-0010")]
public sealed class REQ_QUIC_RFC9000_S3P5_0010
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_AllowsStreamsThatHaveNotBeenResetByThePeer()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x44),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(streamId.Value, resetStreamFrame.StreamId);
        Assert.Equal(0x44UL, resetStreamFrame.ApplicationProtocolErrorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStopSendingFrame_RejectsStreamsThatHaveAlreadyBeenResetByThePeer()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId.Value, 0x99, 0),
            out QuicMaxDataFrame maxDataFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, maxDataFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);

        Assert.False(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(streamId.Value, 0x44),
            out QuicResetStreamFrame resetStreamFrame,
            out errorCode));
        Assert.Equal(default, resetStreamFrame);
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P5-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortStreamReadsAsync_DoesNotSendStopSendingAfterPeerResetStream()
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
        outboundEffects.Clear();

        QuicConnectionTransitionResult resetResult = ReceiveProtectedApplicationPayload(
            runtime,
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(
                streamId: (ulong)stream.Id,
                applicationProtocolErrorCode: 0x22,
                finalSize: 0)));
        Assert.True(resetResult.StateChanged);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            (ulong)stream.Id,
            out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRead, resetSnapshot.ReceiveState);

        outboundEffects.Clear();
        int sentPacketCount = runtime.SendRuntime.SentPackets.Count;

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Equal(sentPacketCount, runtime.SendRuntime.SentPackets.Count);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRead, snapshot.ReceiveState);
    }

    private static QuicConnectionTransitionResult ReceiveProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] protectedPacket));

        Assert.NotNull(runtime.ActivePath);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: 1);
    }
}
