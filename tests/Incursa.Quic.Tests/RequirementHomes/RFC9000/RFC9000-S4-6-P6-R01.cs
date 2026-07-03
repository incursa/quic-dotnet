// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S4-6-P6-R01")]
public sealed class REQ_QUIC_RFC9000_0203
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Requirement("RFC9000-S4-6-P6-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_ReturnsStreamsBlockedFrameWhenThePeerLimitIsReached(bool bidirectional)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 1UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 1UL);

        Assert.True(state.TryOpenLocalStream(bidirectional, out _, out QuicStreamsBlockedFrame firstBlockedFrame));
        Assert.Equal(default, firstBlockedFrame);

        Assert.False(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId blockedStreamId,
            out QuicStreamsBlockedFrame blockedFrame));

        Assert.Equal(default, blockedStreamId);
        Assert.Equal(bidirectional, blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);
    }

    [Fact]
    [Requirement("RFC9000-S4-6-P6-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_ReturnsStreamsBlockedWhenThePeerLimitIsReached()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out _, out _));

        Assert.False(state.TryOpenLocalStream(bidirectional: true, out _, out QuicStreamsBlockedFrame blockedFrame));
        Assert.True(blockedFrame.IsBidirectional);
        Assert.Equal(1UL, blockedFrame.MaximumStreams);
    }
}
