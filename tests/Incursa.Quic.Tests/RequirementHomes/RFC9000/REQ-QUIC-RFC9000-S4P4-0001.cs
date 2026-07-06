// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S4P4-0001")]
public sealed class REQ_QUIC_RFC9000_S4P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P4-0001")]
    [Requirement("REQ-QUIC-RFC9000-S4P4-0002")]
    [Requirement("REQ-QUIC-RFC9000-0185")]
    [Requirement("REQ-QUIC-RFC9000-0186")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReceiveResetStreamFrame_TerminatesOnlyTheReceiveDirectionAndPreservesTheSendDirection()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 32,
            connectionSendLimit: 32,
            peerBidirectionalReceiveLimit: 8,
            peerBidirectionalSendLimit: 8);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame initialFrame));
        Assert.True(state.TryReceiveStreamFrame(initialFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(2UL, state.ConnectionAccountedBytesReceived);

        Assert.True(state.TryReceiveResetStreamFrame(
            new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize: 4),
            out QuicMaxDataFrame maxDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(34UL, maxDataFrame.MaximumData);
        Assert.Equal(34UL, state.ConnectionReceiveLimit);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.True(snapshot.HasFinalSize);
        Assert.Equal(4UL, snapshot.FinalSize);
        Assert.Equal(4UL, snapshot.AccountedBytesReceived);
        Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x33], offset: 2),
            out QuicStreamFrame ignoredFrame));
        Assert.True(state.TryReceiveStreamFrame(ignoredFrame, out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(4UL, state.ConnectionAccountedBytesReceived);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x44], offset: 4),
            out QuicStreamFrame beyondFinalFrame));
        Assert.False(state.TryReceiveStreamFrame(beyondFinalFrame, out errorCode));
        Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

        Assert.True(state.TryReserveSendCapacity(
            1,
            offset: 0,
            length: 1,
            fin: false,
            out QuicDataBlockedFrame dataBlockedFrame,
            out QuicStreamDataBlockedFrame streamDataBlockedFrame,
            out errorCode));
        Assert.Equal(default, dataBlockedFrame);
        Assert.Equal(default, streamDataBlockedFrame);
        Assert.Equal(default, errorCode);

        Assert.True(state.TryGetStreamSnapshot(1, out snapshot));
        Assert.Equal(QuicStreamSendState.Send, snapshot.SendState);
        Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
        Assert.Equal(4UL, snapshot.FinalSize);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P4-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void TryReceiveResetStreamFrame_FuzzTearsDownReceiveStateAndIgnoresLaterDataWithinFinalSize()
    {
        (byte[] InitialData, ulong FinalSize)[] scenarios =
        [
            ([0x11], 2),
            ([0x11, 0x22], 4),
            ([0x11, 0x22, 0x33], 6),
        ];

        foreach ((byte[] initialData, ulong finalSize) in scenarios)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: 32,
                connectionSendLimit: 32,
                peerBidirectionalReceiveLimit: 8,
                peerBidirectionalSendLimit: 8);

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0E, 1, initialData, offset: 0),
                out QuicStreamFrame initialFrame));
            Assert.True(state.TryReceiveStreamFrame(initialFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId: 1, applicationProtocolErrorCode: 0x55, finalSize),
                out QuicMaxDataFrame maxDataFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(maxDataFrame.MaximumData >= 32UL);

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x44], offset: (ulong)initialData.Length),
                out QuicStreamFrame ignoredFrame));
            Assert.True(state.TryReceiveStreamFrame(ignoredFrame, out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
            Assert.Equal(QuicStreamReceiveState.ResetRecvd, snapshot.ReceiveState);
            Assert.Equal(finalSize, snapshot.FinalSize);
            Assert.Equal(QuicStreamSendState.Ready, snapshot.SendState);
        }
    }
}
