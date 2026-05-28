// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-0162")]
public sealed class REQ_QUIC_RFC9000_0162
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0162")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AllowsMultipleStreamsWithinTheConnectionBudget()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 6,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22]), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(5, [0x33, 0x44, 0x55]), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(5UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(2UL, firstSnapshot.AccountedBytesReceived);
        Assert.Equal(2, firstSnapshot.BufferedReadableBytes);
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(3UL, secondSnapshot.AccountedBytesReceived);
        Assert.Equal(3, secondSnapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0162")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AdmitsTheExactConnectionBudgetAcrossStreams()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11]), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(5, [0x22, 0x33, 0x44]), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(1UL, firstSnapshot.AccountedBytesReceived);
        Assert.Equal(1, firstSnapshot.BufferedReadableBytes);
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(3UL, secondSnapshot.AccountedBytesReceived);
        Assert.Equal(3, secondSnapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0162")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_LimitsTheTotalStreamDataBytesAcrossTheConnection()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 5, [0x33, 0x44], offset: 0),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 9, [0x55], offset: 0),
            out QuicStreamFrame connectionLimitFrame));
        Assert.False(state.TryReceiveStreamFrame(connectionLimitFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] data, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data, offset: offset),
            out QuicStreamFrame frame));
        return frame;
    }
}
