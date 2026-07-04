// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("RFC9000-S3-2-P7-S2-R01")]
public sealed class RFC9000_S3_2_P7_S2_R01
{
    [Fact]
    [Requirement("RFC9000-S3-2-P7-S2-R01")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_EntersSizeKnownWhenFinArrives()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(connectionReceiveLimit: 32, peerBidirectionalReceiveLimit: 8);

        byte[] nonFinPacket = QuicStreamTestData.BuildStreamFrame(0x0E, streamId: 5, [0x33, 0x44], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(nonFinPacket, out QuicStreamFrame nonFinFrame));

        Assert.True(state.TryReceiveStreamFrame(nonFinFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot preFinSnapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, preFinSnapshot.ReceiveState);
        Assert.False(preFinSnapshot.HasFinalSize);

        byte[] finPacket = QuicStreamTestData.BuildStreamFrame(0x0F, streamId: 5, [0x33, 0x44], offset: 2);
        Assert.True(QuicStreamParser.TryParseStreamFrame(finPacket, out QuicStreamFrame finFrame));

        Assert.True(state.TryReceiveStreamFrame(finFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
    }
}
