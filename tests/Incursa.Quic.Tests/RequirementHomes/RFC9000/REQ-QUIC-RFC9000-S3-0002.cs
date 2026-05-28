// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S3-0002")]
public sealed class REQ_QUIC_RFC9000_S3_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryOpenLocalStream_UsesBothStateMachinesForLocalBidirectionalStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(state.TryOpenLocalStream(bidirectional: true, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
        Assert.Equal(default, blockedFrame);

        Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);
    }
}
