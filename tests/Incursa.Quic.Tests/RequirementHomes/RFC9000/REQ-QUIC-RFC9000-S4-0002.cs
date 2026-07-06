// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4-0002")]
public sealed class REQ_QUIC_RFC9000_S4_0002
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReceiveStreamFrame_AllowsBytesWithinTheAdvertisedLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 2);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(5, [0x22], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(1UL, firstSnapshot.UniqueBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(1UL, secondSnapshot.UniqueBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveStreamFrame_AllowsBytesAtTheAdvertisedLimits()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 2);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x11, 0x22], offset: 0), out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(5, [0x33, 0x44], offset: 0), out errorCode));
        Assert.Equal(default, errorCode);

        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot firstSnapshot));
        Assert.Equal(2UL, firstSnapshot.UniqueBytesReceived);
        Assert.True(state.TryGetStreamSnapshot(5, out QuicConnectionStreamSnapshot secondSnapshot));
        Assert.Equal(2UL, secondSnapshot.UniqueBytesReceived);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReceiveStreamFrame_LimitsBytesOnStreamsAndAcrossTheConnection()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4,
            peerBidirectionalReceiveLimit: 2);

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
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x55], offset: 2),
            out QuicStreamFrame streamLimitFrame));
        Assert.False(state.TryReceiveStreamFrame(streamLimitFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 9, [0x66], offset: 0),
            out QuicStreamFrame connectionLimitFrame));
        Assert.False(state.TryReceiveStreamFrame(connectionLimitFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryReceiveStreamFrame_FuzzEnforcesStreamAndConnectionReceiveLimits()
    {
        (ulong ConnectionLimit, ulong StreamLimit, byte[] FirstData, byte[] SecondData)[] scenarios =
        [
            (4, 2, [0x11], [0x22]),
            (6, 3, [0x11, 0x12], [0x21, 0x22]),
            (8, 4, [0x11, 0x12, 0x13], [0x21, 0x22, 0x23]),
        ];

        foreach ((ulong connectionLimit, ulong streamLimit, byte[] firstData, byte[] secondData) in scenarios)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: connectionLimit,
                peerBidirectionalReceiveLimit: streamLimit);

            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(1, firstData, offset: 0), out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryReceiveStreamFrame(ParseStreamFrame(5, secondData, offset: 0), out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)(firstData.Length + secondData.Length), state.ConnectionAccountedBytesReceived);

            Assert.False(state.TryReceiveStreamFrame(ParseStreamFrame(1, [0x55], streamLimit), out errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);

            ulong remainingConnectionCredit = connectionLimit - state.ConnectionAccountedBytesReceived;
            byte[] overConnectionLimitData = new byte[(int)remainingConnectionCredit + 1];
            Assert.False(state.TryReceiveStreamFrame(ParseStreamFrame(9, overConnectionLimitData, offset: 0), out errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
        }
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, byte[] streamData, ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, streamData, offset: offset),
            out QuicStreamFrame frame));

        return frame;
    }
}
