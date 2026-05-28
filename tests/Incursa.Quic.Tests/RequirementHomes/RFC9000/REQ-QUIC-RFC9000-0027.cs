// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0027")]
public sealed class REQ_QUIC_RFC9000_0027
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamState_AllowsMultipleLocalStreamsToRemainOpenTogether()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            peerBidirectionalStreamLimit: 4,
            peerUnidirectionalStreamLimit: 4);

        ulong[] bidirectionalStreamIds = OpenLocalStreams(state, bidirectional: true, count: 4);
        ulong[] unidirectionalStreamIds = OpenLocalStreams(state, bidirectional: false, count: 4);

        AssertLocalStreamsRemainOpen(state, bidirectionalStreamIds, QuicStreamReceiveState.Recv);
        AssertLocalStreamsRemainOpen(state, unidirectionalStreamIds, QuicStreamReceiveState.None);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0027")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamState_AllowsMultiplePeerStreamsToRemainOpenTogether()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 64,
            incomingBidirectionalStreamLimit: 4,
            incomingUnidirectionalStreamLimit: 4,
            peerBidirectionalReceiveLimit: 8,
            peerUnidirectionalReceiveLimit: 8);

        ulong[] bidirectionalStreamIds = ReceivePeerStreamFrames(state, firstStreamId: 1, count: 4);
        ulong[] unidirectionalStreamIds = ReceivePeerStreamFrames(state, firstStreamId: 3, count: 4);

        Assert.Equal(8UL, state.ConnectionAccountedBytesReceived);
        AssertPeerStreamsRemainOpen(state, bidirectionalStreamIds, QuicStreamSendState.Ready);
        AssertPeerStreamsRemainOpen(state, unidirectionalStreamIds, QuicStreamSendState.None);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0027")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void StreamState_EnforcesConfiguredConcurrentStreamLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 64,
            incomingBidirectionalStreamLimit: 1,
            peerBidirectionalStreamLimit: 1,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.False(state.TryOpenLocalStream(
            bidirectional: true,
            out _,
            out blockedFrame));
        Assert.NotEqual(default, blockedFrame);

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x31]),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.False(state.TryReceiveStreamFrame(
            ParseStreamFrame(5, [0x51]),
            out errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamLimitError, errorCode);
    }

    private static ulong[] OpenLocalStreams(QuicConnectionStreamState state, bool bidirectional, int count)
    {
        ulong[] streamIds = new ulong[count];
        for (int index = 0; index < streamIds.Length; index++)
        {
            Assert.True(state.TryOpenLocalStream(
                bidirectional,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            streamIds[index] = streamId.Value;
        }

        return streamIds;
    }

    private static ulong[] ReceivePeerStreamFrames(QuicConnectionStreamState state, ulong firstStreamId, int count)
    {
        ulong[] streamIds = new ulong[count];
        for (int index = 0; index < streamIds.Length; index++)
        {
            ulong streamId = firstStreamId + ((ulong)index << 2);
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(streamId, [(byte)(0x20 + index)]),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            streamIds[index] = streamId;
        }

        return streamIds;
    }

    private static void AssertLocalStreamsRemainOpen(
        QuicConnectionStreamState state,
        ulong[] streamIds,
        QuicStreamReceiveState expectedReceiveState)
    {
        foreach (ulong streamId in streamIds)
        {
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
            Assert.Equal(expectedReceiveState, snapshot.ReceiveState);
        }
    }

    private static void AssertPeerStreamsRemainOpen(
        QuicConnectionStreamState state,
        ulong[] streamIds,
        QuicStreamSendState expectedSendState)
    {
        foreach (ulong streamId in streamIds)
        {
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(expectedSendState, snapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
            Assert.Equal(1UL, snapshot.UniqueBytesReceived);
        }
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] streamData)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, streamData),
            out QuicStreamFrame frame));

        return frame;
    }
}
