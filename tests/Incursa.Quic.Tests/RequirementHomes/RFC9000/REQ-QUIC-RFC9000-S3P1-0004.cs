// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3P1-0004")]
public sealed class REQ_QUIC_RFC9000_S3P1_0004
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0004")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_AllocatesAStreamIdBeforeTheFirstStreamFrameIsSent()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(streamId.Value, snapshot.StreamId);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.False(snapshot.HasFinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0004")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReserveSendCapacity_OnABlockedFirstOutboundFrameKeepsTheAllocatedStreamId()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionSendLimit: 16,
            localBidirectionalSendLimit: 0);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(streamId.Value, readySnapshot.StreamId);
        Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);

        Assert.False(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(streamId.Value, streamDataBlockedFrame.StreamId);
        Assert.Equal(0UL, streamDataBlockedFrame.MaximumStreamData);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot blockedSnapshot));
        Assert.Equal(streamId.Value, blockedSnapshot.StreamId);
        Assert.Equal(QuicStreamSendState.Send, blockedSnapshot.SendState);
    }
}
