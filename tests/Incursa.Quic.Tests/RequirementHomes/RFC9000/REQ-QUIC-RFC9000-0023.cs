// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0023")]
public sealed class REQ_QUIC_RFC9000_0023
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void StreamState_AllowsLocalAndPeerInitiatedStreamCreation()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalStreamLimit: 2,
            incomingBidirectionalStreamLimit: 2,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: true,
            out QuicStreamId localStreamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);
        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 1, [0x31]), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(localStreamId.Value, out QuicConnectionStreamSnapshot localSnapshot));
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot peerSnapshot));
        Assert.Equal(localStreamId.Value, localSnapshot.StreamId);
        Assert.Equal(QuicStreamSendState.Ready, localSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, localSnapshot.ReceiveState);
        Assert.Equal(1UL, peerSnapshot.StreamId);
        Assert.Equal(QuicStreamSendState.Ready, peerSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, peerSnapshot.ReceiveState);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_RejectsPeerCreationOfALocalInitiatedStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            peerBidirectionalReceiveLimit: 8);

        Assert.False(state.TryReceiveStreamFrame(ParseStreamFrame(streamId: 0, [0x41]), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);
        Assert.False(state.TryGetStreamSnapshot(0, out _));
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] streamData)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, streamData),
            out QuicStreamFrame frame));

        return frame;
    }
}
