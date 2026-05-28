// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3-0003")]
public sealed class REQ_QUIC_RFC9000_S3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0003")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReserveSendCapacity_AdvancesOnlyTheSendPartOfABidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
        Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, readySnapshot.ReceiveState);

        Assert.True(state.TryReserveSendCapacity(
            streamId.Value,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot sendSnapshot));
        Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, sendSnapshot.ReceiveState);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId.Value, [0xAA]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot completedSnapshot));
        Assert.Equal(QuicStreamSendState.Send, completedSnapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, completedSnapshot.ReceiveState);
        Assert.True(completedSnapshot.HasFinalSize);
        Assert.Equal(1UL, completedSnapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0003")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AdvancesOnlyTheReceivePartOfABidirectionalStream()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            connectionSendLimit: 16);

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        byte[] packet = QuicStreamTestData.BuildStreamFrame(0x0F, streamId.Value, [0x11, 0x22]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packet, out QuicStreamFrame frame));

        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(2UL, snapshot.FinalSize);
    }
}
