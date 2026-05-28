// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0031")]
public sealed class REQ_QUIC_RFC9000_0031
{
    [Theory]
    [InlineData(false, 0UL, 2UL, 4UL, 6UL)]
    [InlineData(true, 1UL, 3UL, 5UL, 7UL)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_AssignsUniqueStreamIdsAcrossTheConnection(
        bool isServer,
        ulong firstBidirectionalStreamId,
        ulong firstUnidirectionalStreamId,
        ulong secondBidirectionalStreamId,
        ulong secondUnidirectionalStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(isServer: isServer);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId firstBidirectional, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(firstBidirectionalStreamId, firstBidirectional.Value);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId firstUnidirectional, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(firstUnidirectionalStreamId, firstUnidirectional.Value);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId secondBidirectional, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(secondBidirectionalStreamId, secondBidirectional.Value);

        Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId secondUnidirectional, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(secondUnidirectionalStreamId, secondUnidirectional.Value);

        ulong[] streamIds =
        [
            firstBidirectional.Value,
            firstUnidirectional.Value,
            secondBidirectional.Value,
            secondUnidirectional.Value
        ];

        Assert.Equal(streamIds.Length, streamIds.Distinct().Count());
    }

    [Theory]
    [InlineData(false, true, 0UL)]
    [InlineData(false, false, 2UL)]
    [InlineData(true, true, 1UL)]
    [InlineData(true, false, 3UL)]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_DoesNotConsumeAStreamIdWhenBlocked(
        bool isServer,
        bool bidirectional,
        ulong expectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            isServer: isServer,
            peerBidirectionalStreamLimit: bidirectional ? 0UL : 1UL,
            peerUnidirectionalStreamLimit: bidirectional ? 1UL : 0UL);

        Assert.False(state.TryOpenLocalStream(bidirectional, out QuicStreamId blockedStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(0UL, blockedFrame.MaximumStreams);

        Assert.True(state.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 1)));

        Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId openedStreamId, out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(expectedStreamId, openedStreamId.Value);
    }
}
