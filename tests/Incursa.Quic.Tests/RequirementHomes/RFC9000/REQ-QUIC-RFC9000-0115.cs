// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0115")]
public sealed class REQ_QUIC_RFC9000_0115
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0115")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_KeepsDataRecvdUntilApplicationReadsIt()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);
        ulong streamId = 5;

        byte[] tail = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0x33, 0x44], offset: 2);
        byte[] head = QuicStreamTestData.BuildStreamFrame(0x0E, streamId, [0x11, 0x22], offset: 0);

        Assert.True(QuicStreamParser.TryParseStreamFrame(tail, out QuicStreamFrame tailFrame));
        Assert.True(QuicStreamParser.TryParseStreamFrame(head, out QuicStreamFrame headFrame));

        Assert.True(state.TryReceiveStreamFrame(tailFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(headFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.NotEqual(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.UniqueBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0115")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_LeavesDataRecvdAfterApplicationReadsFinalBytes()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);
        ulong streamId = 5;

        byte[] complete = QuicStreamTestData.BuildStreamFrame(0x0F, streamId, [0x11, 0x22, 0x33, 0x44], offset: 0);
        Assert.True(QuicStreamParser.TryParseStreamFrame(complete, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot preReadSnapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, preReadSnapshot.ReceiveState);

        Span<byte> destination = stackalloc byte[4];
        Assert.True(state.TryReadStreamData(
            streamId,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(4, bytesWritten);
        Assert.True(completed);
        Assert.True(new byte[] { 0x11, 0x22, 0x33, 0x44 }.AsSpan().SequenceEqual(destination));
        Assert.Equal(36UL, maxDataFrame.MaximumData);
        Assert.Equal(streamId, maxStreamDataFrame.StreamId);
        Assert.Equal(12UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRead, snapshot.ReceiveState);
        Assert.NotEqual(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }
}
