// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0021")]
public sealed class REQ_QUIC_RFC9000_0021
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_OpensCarriesDataAndClosesPeerStreamWithOneFrame()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 16);
        byte[] payload = [0x41, 0x42, 0x43];

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0B,
            streamId: 1,
            payload);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preReadSnapshot));
        Assert.True(preReadSnapshot.HasFinalSize);
        Assert.Equal((ulong)payload.Length, preReadSnapshot.FinalSize);
        Assert.Equal((ulong)payload.Length, preReadSnapshot.UniqueBytesReceived);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, preReadSnapshot.ReceiveState);

        Span<byte> destination = stackalloc byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(completed);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
        Assert.NotEqual(default, maxDataFrame);
        Assert.NotEqual(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.Equal((ulong)payload.Length, snapshot.ReadOffset);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_DoesNotCloseStreamWhenFinIsAbsent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 16);
        byte[] payload = [0x51, 0x52];

        QuicStreamFrame frame = QuicS19P8StreamFrameTestSupport.Parse(
            frameType: 0x0A,
            streamId: 1,
            payload);

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot preReadSnapshot));
        Assert.False(preReadSnapshot.HasFinalSize);
        Assert.Equal(QuicStreamReceiveState.Recv, preReadSnapshot.ReceiveState);

        Span<byte> destination = stackalloc byte[payload.Length];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.False(completed);
        Assert.True(payload.AsSpan().SequenceEqual(destination));
        Assert.NotEqual(default, maxDataFrame);
        Assert.NotEqual(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.False(snapshot.HasFinalSize);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }
}
