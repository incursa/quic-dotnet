// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P1-0002")]
public sealed class REQ_QUIC_RFC9000_S4P1_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AllowsEachStreamThroughItsOwnReceiveLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 8,
            peerBidirectionalReceiveLimit: 4);

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44]),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(5, [0x55, 0x66, 0x77, 0x88]),
            out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(8UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(4UL, firstSnapshot.ReceiveLimit);
        Assert.Equal(4UL, firstSnapshot.AccountedBytesReceived);
        Assert.Equal(4, firstSnapshot.BufferedReadableBytes);
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(4UL, secondSnapshot.ReceiveLimit);
        Assert.Equal(4UL, secondSnapshot.AccountedBytesReceived);
        Assert.Equal(4, secondSnapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_LimitsThePerStreamReceiveBufferUse()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 2);

        QuicStreamFrame firstFrame = ParseStreamFrame(1, [0x11, 0x22]);
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        QuicStreamFrame secondFrame = ParseStreamFrame(5, [0x33, 0x44]);
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        QuicStreamFrame overflowFrame = ParseStreamFrame(1, [0x55], offset: 2);
        Assert.False(state.TryReceiveStreamFrame(overflowFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_AdvancesOnlyTheConsumedStreamReceiveLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 16,
            peerBidirectionalReceiveLimit: 4);

        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(1, [0x11, 0x22, 0x33, 0x44]),
            out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.True(state.TryReceiveStreamFrame(
            ParseStreamFrame(5, [0x55, 0x66, 0x77, 0x88]),
            out errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.False(completed);
        Assert.True(new byte[] { 0x11, 0x22 }.AsSpan().SequenceEqual(destination[..bytesWritten]));
        Assert.Equal(18UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(6UL, maxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot consumedSnapshot));
        Assert.Equal(6UL, consumedSnapshot.ReceiveLimit);
        Assert.Equal(2UL, consumedSnapshot.ReadOffset);
        Assert.Equal(2, consumedSnapshot.BufferedReadableBytes);
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot untouchedSnapshot));
        Assert.Equal(4UL, untouchedSnapshot.ReceiveLimit);
        Assert.Equal(0UL, untouchedSnapshot.ReadOffset);
        Assert.Equal(4, untouchedSnapshot.BufferedReadableBytes);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x99, 0xAA], offset: 4), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.False(state.TryReceiveStreamFrame(ParseStreamFrame(5, [0xBB], offset: 4), out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] data, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data, offset: offset),
            out QuicStreamFrame frame));
        return frame;
    }
}
