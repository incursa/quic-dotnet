// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S4-6-P3-R01")]
public sealed class REQ_QUIC_RFC9000_0200
{
    [Theory]
    [InlineData(true, 0UL, 4UL)]
    [InlineData(false, 2UL, 6UL)]
    [Requirement("RFC9000-S4-6-P3-R01")]
    [Requirement("REQ-QUIC-RFC9000-0034")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_AllowsStreamsWithinThePeerStreamLimit(
        bool bidirectional,
        ulong firstExpectedStreamId,
        ulong secondExpectedStreamId)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: bidirectional ? 2UL : 4UL,
            peerUnidirectionalStreamLimit: bidirectional ? 4UL : 2UL);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId firstStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(firstExpectedStreamId, firstStreamId.Value);

        Assert.True(state.TryOpenLocalStream(
            bidirectional,
            out QuicStreamId secondStreamId,
            out blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.Equal(secondExpectedStreamId, secondStreamId.Value);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.True(state.TryGetStreamSnapshot(secondStreamId.Value, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(QuicStreamSendState.Ready, firstSnapshot.SendState);
        Assert.Equal(QuicStreamSendState.Ready, secondSnapshot.SendState);
    }

    [Fact]
    [Requirement("RFC9000-S4-6-P3-R01")]
    [Requirement("REQ-QUIC-RFC9000-0034")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryOpenLocalStream_DoesNotExceedThePeerBidirectionalStreamLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(peerBidirectionalStreamLimit: 1);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId firstStreamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(firstStreamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);

        Assert.False(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId secondStreamId, out blockedFrame));
        Assert.Equal(default, secondStreamId);
    }

    [Fact]
    [Requirement("RFC9000-S4-6-P3-R01")]
    [Requirement("REQ-QUIC-RFC9000-0034")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_TryOpenLocalStream_OpensExactlyThePeerAdvertisedStreamLimit()
    {
        foreach (bool bidirectional in new[] { true, false })
        {
            for (int streamLimit = 1; streamLimit <= 5; streamLimit++)
            {
                QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                    peerBidirectionalStreamLimit: bidirectional ? (ulong)streamLimit : 8UL,
                    peerUnidirectionalStreamLimit: bidirectional ? 8UL : (ulong)streamLimit);

                for (int streamIndex = 0; streamIndex < streamLimit; streamIndex++)
                {
                    Assert.True(state.TryOpenLocalStream(
                        bidirectional,
                        out QuicStreamId streamId,
                        out QuicStreamsBlockedFrame blockedFrame));
                    Assert.Equal(default, blockedFrame);
                    Assert.Equal(LocalStreamId(bidirectional, streamIndex), streamId.Value);
                }

                Assert.False(state.TryOpenLocalStream(
                    bidirectional,
                    out QuicStreamId overLimitStreamId,
                    out QuicStreamsBlockedFrame overLimitBlockedFrame));
                Assert.Equal(default, overLimitStreamId);
                Assert.Equal(bidirectional, overLimitBlockedFrame.IsBidirectional);
                Assert.Equal((ulong)streamLimit, overLimitBlockedFrame.MaximumStreams);
            }
        }
    }

    private static ulong LocalStreamId(bool bidirectional, int streamIndex)
    {
        ulong unidirectionalBit = bidirectional ? 0UL : 2UL;
        return ((ulong)streamIndex << 2) | unidirectionalBit;
    }
}
