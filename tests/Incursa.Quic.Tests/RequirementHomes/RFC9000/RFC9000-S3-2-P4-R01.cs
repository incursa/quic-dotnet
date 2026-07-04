// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using FsCheck.Xunit;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="RFC9000-S3-2-P4-R01">An endpoint MUST enter Recv when the peer-side sending part opens.</workbench-requirement>
/// </workbench-requirements>
[Requirement("RFC9000-S3-2-P4-R01")]
public sealed class RFC9000_S3_2_P4_R01
{
    [Property]
    [Requirement("RFC9000-S3-2-P4-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryApplyMaxStreamDataFrame_EntersRecvWhenPeerSideSendingPartOpens(byte streamIndex)
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
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

        ulong streamId = ((ulong)streamIndex << 2) | 1UL;

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

        Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId, 16), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId, out snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }

    [Fact]
    [Requirement("RFC9000-S3-2-P4-R01")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryApplyMaxStreamDataFrame_LeavesLocalUnidirectionalReceiveStateUnchanged()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 128,
            connectionSendLimit: 128,
            localUnidirectionalSendLimit: 8,
            peerUnidirectionalStreamLimit: 32);

        Assert.True(state.TryOpenLocalStream(
            bidirectional: false,
            out QuicStreamId streamId,
            out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshotBefore));
        Assert.Equal(QuicStreamSendState.Ready, snapshotBefore.SendState);
        Assert.Equal(QuicStreamReceiveState.None, snapshotBefore.ReceiveState);

        Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, 16), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshotAfter));
        Assert.Equal(QuicStreamSendState.Ready, snapshotAfter.SendState);
        Assert.Equal(QuicStreamReceiveState.None, snapshotAfter.ReceiveState);
        Assert.Equal(16UL, snapshotAfter.SendLimit);
    }
}
