// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_FlowControl_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0082")]
    [Requirement("REQ-QUIC-RFC9000-0083")]
    [Requirement("REQ-QUIC-RFC9000-0163")]
    [Requirement("REQ-QUIC-RFC9000-0176")]
    [Requirement("REQ-QUIC-RFC9000-0177")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void SendFlowControlFuzz_EmitsBlockedSignalsUntilCreditAllowsFinAndDataSent()
    {
        for (int iteration = 1; iteration <= 8; iteration++)
        {
            ulong streamLimit = (ulong)iteration;
            QuicConnectionStreamState streamBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 64,
                localBidirectionalSendLimit: streamLimit);
            Assert.True(streamBlockedState.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamBlockedStreamId,
                out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.False(streamBlockedState.TryReserveSendCapacity(
                streamBlockedStreamId.Value,
                offset: 0,
                length: iteration + 1,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(streamBlockedStreamId.Value, streamDataBlockedFrame.StreamId);
            Assert.Equal(streamLimit, streamDataBlockedFrame.MaximumStreamData);

            Assert.False(streamBlockedState.TryReserveSendCapacity(
                streamBlockedStreamId.Value,
                offset: 0,
                length: iteration + 1,
                fin: false,
                out dataBlockedFrame,
                out QuicStreamDataBlockedFrame repeatedStreamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(streamDataBlockedFrame, repeatedStreamDataBlockedFrame);

            Assert.True(streamBlockedState.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(streamBlockedStreamId.Value, streamLimit + 1),
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(streamBlockedState.TryReserveSendCapacity(
                streamBlockedStreamId.Value,
                offset: 0,
                length: iteration + 1,
                fin: true,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);
            Assert.True(streamBlockedState.TryGetStreamSnapshot(
                streamBlockedStreamId.Value,
                out QuicConnectionStreamSnapshot dataSentSnapshot));
            Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
            Assert.True(dataSentSnapshot.HasFinalSize);
            Assert.Equal(streamLimit + 1, dataSentSnapshot.FinalSize);

            QuicConnectionStreamState connectionBlockedState = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: streamLimit,
                localBidirectionalSendLimit: 64);
            Assert.True(connectionBlockedState.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId connectionBlockedStreamId,
                out blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.False(connectionBlockedState.TryReserveSendCapacity(
                connectionBlockedStreamId.Value,
                offset: 0,
                length: iteration + 1,
                fin: false,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(streamLimit, dataBlockedFrame.MaximumData);
            Assert.Equal(default, streamDataBlockedFrame);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0162")]
    [Requirement("REQ-QUIC-RFC9000-0163")]
    [Requirement("REQ-QUIC-RFC9000-0170")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReceiveFlowControlFuzz_TracksCumulativeConnectionBytesAndRejectsExcess()
    {
        for (int iteration = 1; iteration <= 8; iteration++)
        {
            ulong firstStreamId = 1;
            ulong secondStreamId = 5;
            ulong thirdStreamId = 9;
            byte[] firstPayload = Enumerable.Repeat((byte)(0x10 + iteration), iteration).ToArray();
            byte[] secondPayload = Enumerable.Repeat((byte)(0x20 + iteration), iteration + 1).ToArray();
            ulong connectionLimit = (ulong)(firstPayload.Length + secondPayload.Length);
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: connectionLimit,
                incomingBidirectionalStreamLimit: 4,
                peerBidirectionalReceiveLimit: 64);

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(firstStreamId, firstPayload),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(secondStreamId, secondPayload),
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(connectionLimit, state.ConnectionAccountedBytesReceived);

            Assert.True(state.TryGetStreamSnapshot(firstStreamId, out QuicConnectionStreamSnapshot firstSnapshot));
            Assert.True(state.TryGetStreamSnapshot(secondStreamId, out QuicConnectionStreamSnapshot secondSnapshot));
            Assert.Equal((ulong)firstPayload.Length, firstSnapshot.AccountedBytesReceived);
            Assert.Equal((ulong)secondPayload.Length, secondSnapshot.AccountedBytesReceived);

            Assert.False(state.TryReceiveStreamFrame(
                ParseStreamFrame(thirdStreamId, [(byte)(0x30 + iteration)]),
                out errorCode));
            Assert.Equal(QuicTransportErrorCode.FlowControlError, errorCode);
            Assert.Equal(connectionLimit, state.ConnectionAccountedBytesReceived);
            if (state.TryGetStreamSnapshot(thirdStreamId, out QuicConnectionStreamSnapshot rejectedSnapshot))
            {
                Assert.Equal(0UL, rejectedSnapshot.AccountedBytesReceived);
                Assert.Equal(0, rejectedSnapshot.BufferedReadableBytes);
            }
        }
    }

    private static QuicStreamFrame ParseStreamFrame(ulong streamId, ReadOnlySpan<byte> data)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, streamId, data),
            out QuicStreamFrame frame));
        return frame;
    }
}
