// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0002")]
public sealed class REQ_QUIC_RFC9000_S19P4_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveResetStreamFrame_DiscardsBufferedDataAfterReset()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0A, 1, [0x11, 0x22, 0x33, 0x44], offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(state.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot bufferedSnapshot));
        Assert.Equal(4, bufferedSnapshot.BufferedReadableBytes);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 4),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));
        _ = maxDataFrame;
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot resetSnapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);
        Assert.Equal(0, resetSnapshot.BufferedReadableBytes);

        Span<byte> destination = stackalloc byte[4];
        Assert.False(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));
        Assert.Equal(0, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);
        Assert.Equal(default, errorCode);
    }
}
