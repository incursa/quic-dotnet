// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicConnectionStreamWritePreparationTests
{
    [Fact]
    public void PrepareStreamWrite_ResolvesCapturesAndReservesAtomically()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 128,
            localBidirectionalSendLimit: 128);
        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _));
        Assert.True(state.TrySetStreamPriority(streamId.Value, priority: -7));

        QuicConnectionStreamWritePreparationStatus status = state.PrepareStreamWrite(
            streamId.Value,
            length: 32,
            fin: false,
            out QuicConnectionStreamWritePreparation preparation,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode);

        Assert.Equal(QuicConnectionStreamWritePreparationStatus.Reserved, status);
        Assert.Equal(0UL, preparation.WriteOffset);
        Assert.Equal(QuicStreamSendState.Ready, preparation.SendStateBeforeWrite.SendState);
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(32UL, snapshot.UniqueBytesSent);
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
    }

    [Fact]
    public void PrepareStreamWrite_OpensTheExactNextLocalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 128,
            localBidirectionalSendLimit: 128);

        QuicConnectionStreamWritePreparationStatus status = state.PrepareStreamWrite(
            streamIdValue: 0,
            length: 16,
            fin: false,
            out QuicConnectionStreamWritePreparation preparation,
            out _,
            out _,
            out QuicTransportErrorCode errorCode);

        Assert.Equal(QuicConnectionStreamWritePreparationStatus.Reserved, status);
        Assert.Equal(0UL, preparation.WriteOffset);
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(0, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(16UL, snapshot.UniqueBytesSent);
    }

    [Fact]
    public void PrepareStreamWrite_ReturnsBlockedWithoutMutatingTheRollbackSnapshot()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 8,
            localBidirectionalSendLimit: 64);
        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _));

        QuicConnectionStreamWritePreparationStatus status = state.PrepareStreamWrite(
            streamId.Value,
            length: 16,
            fin: false,
            out QuicConnectionStreamWritePreparation preparation,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode);

        Assert.Equal(QuicConnectionStreamWritePreparationStatus.Blocked, status);
        Assert.Equal(default, preparation);
        Assert.Equal(8UL, dataBlockedFrame.MaximumData);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.UniqueBytesSent);
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
    }

    [Fact]
    public void PrepareStreamWrite_DistinguishesUnavailableNotWritableAndCompletedStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 128,
            localBidirectionalSendLimit: 128,
            peerUnidirectionalReceiveLimit: 128);

        Assert.Equal(
            QuicConnectionStreamWritePreparationStatus.Unavailable,
            state.PrepareStreamWrite(4, 1, fin: false, out _, out _, out _, out QuicTransportErrorCode unavailableError));
        Assert.Equal(default, unavailableError);

        Assert.Equal(
            QuicConnectionStreamWritePreparationStatus.Unavailable,
            state.PrepareStreamWrite(1, 1, fin: false, out _, out _, out _, out QuicTransportErrorCode peerInitiatedError));
        Assert.Equal(default, peerInitiatedError);

        byte[] payload = [1];
        QuicStreamFrame peerUnidirectionalFrame = new(
            0x0A,
            new QuicStreamId(3),
            hasOffset: false,
            offset: 0,
            hasLength: true,
            length: 1,
            fin: false,
            payload,
            payload.Length);
        Assert.True(state.TryReceiveStreamFrame(peerUnidirectionalFrame, out _));
        Assert.Equal(
            QuicConnectionStreamWritePreparationStatus.NotWritable,
            state.PrepareStreamWrite(3, 1, fin: false, out _, out _, out _, out _));

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId localStreamId, out _));
        Assert.Equal(
            QuicConnectionStreamWritePreparationStatus.Reserved,
            state.PrepareStreamWrite(localStreamId.Value, 0, fin: true, out _, out _, out _, out _));
        Assert.Equal(
            QuicConnectionStreamWritePreparationStatus.Completed,
            state.PrepareStreamWrite(localStreamId.Value, 0, fin: true, out _, out _, out _, out _));
    }

    [Fact]
    public void PrepareStreamWrite_ReturnsSnapshotThatRestoresReservedState()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 128,
            localBidirectionalSendLimit: 128);
        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out _));

        Assert.Equal(
            QuicConnectionStreamWritePreparationStatus.Reserved,
            state.PrepareStreamWrite(streamId.Value, 32, fin: false, out QuicConnectionStreamWritePreparation preparation, out _, out _, out _));
        Assert.True(state.TryRestoreSendState(preparation.SendStateBeforeWrite));

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.UniqueBytesSent);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
    }
}
