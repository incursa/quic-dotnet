// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S3P2-0010">Either frame MAY arrive before a STREAM or STREAM_DATA_BLOCKED frame if packets are lost or reordered.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
public sealed class REQ_QUIC_RFC9000_S3P2_0010
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStopSendingFrame_AllowsStreamFrameAfterReorderedPeerStopSending()
    {
        QuicConnectionStreamState state = CreatePeerBidirectionalStreamState();

        Assert.True(state.TryReceiveStopSendingFrame(
            new QuicStopSendingFrame(1, 0x99),
            out QuicResetStreamFrame resetStreamFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(1UL, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0xBB]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.ResetSent, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(0UL, snapshot.FinalSize);
        Assert.Equal(1UL, snapshot.UniqueBytesReceived);
        Assert.Equal(1, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryApplyMaxStreamDataFrame_AllowsStreamDataBlockedFrameAfterReorderedPeerCredit()
    {
        QuicConnectionStreamState state = CreatePeerBidirectionalStreamState();

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamDataBlockedFrame(
            new QuicStreamDataBlockedFrame(1, 16),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamType.Bidirectional, snapshot.StreamType);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
        Assert.Equal(16UL, snapshot.SendLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_RejectsPeerInitiatedUnidirectionalStreamsBeforeAnyStreamFrame()
    {
        QuicConnectionStreamState state = CreatePeerBidirectionalStreamState();

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(3, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(QuicTransportErrorCode.StreamStateError, errorCode);

        Assert.False(state.TryGetStreamSnapshot(3, out _));
    }

    private static QuicConnectionStreamState CreatePeerBidirectionalStreamState()
    {
        return QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 32,
            peerUnidirectionalReceiveLimit: 32,
            localBidirectionalReceiveLimit: 32,
            localUnidirectionalSendLimit: 32,
            peerBidirectionalSendLimit: 8);
    }
}
