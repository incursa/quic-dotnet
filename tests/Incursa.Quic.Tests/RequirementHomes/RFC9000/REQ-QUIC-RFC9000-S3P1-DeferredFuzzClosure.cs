// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S3P1_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0003")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0004")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void SendStateFuzz_FirstOutboundFrameAllocatesStreamIdAndContinuesProcessingMaxStreamData()
    {
        for (int iteration = 0; iteration < 32; iteration++)
        {
            bool bidirectional = (iteration & 1) == 0;
            ulong initialStreamLimit = 1UL + (ulong)(iteration % 3);
            ulong expandedStreamLimit = initialStreamLimit + 4UL;
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 256,
                localBidirectionalSendLimit: initialStreamLimit,
                localUnidirectionalSendLimit: initialStreamLimit);

            Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot readySnapshot));
            Assert.Equal(streamId.Value, readySnapshot.StreamId);
            Assert.Equal(QuicStreamSendState.Ready, readySnapshot.SendState);

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
            Assert.Equal(streamId.Value, sendSnapshot.StreamId);
            Assert.Equal(QuicStreamSendState.Send, sendSnapshot.SendState);

            Assert.True(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, expandedStreamLimit), out errorCode));
            Assert.Equal(default, errorCode);
            Assert.False(state.TryApplyMaxStreamDataFrame(new QuicMaxStreamDataFrame(streamId.Value, expandedStreamLimit - 1), out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 1,
                length: (int)(expandedStreamLimit - 1),
                fin: true,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
            Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
            Assert.Equal(expandedStreamLimit, dataSentSnapshot.FinalSize);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0011")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DataSentFuzz_RetransmitsWithoutAdditionalFlowControlOrBlockedFrames()
    {
        for (int length = 1; length <= 32; length++)
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: (ulong)length,
                localUnidirectionalSendLimit: (ulong)length);

            Assert.True(state.TryOpenLocalStream(bidirectional: false, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            Assert.True(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length,
                fin: true,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot dataSentSnapshot));
            Assert.Equal(QuicStreamSendState.DataSent, dataSentSnapshot.SendState);
            Assert.Equal((ulong)length, state.ConnectionUniqueBytesSent);

            Assert.True(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length,
                fin: false,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)length, state.ConnectionUniqueBytesSent);

            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: (ulong)length,
                length: 1,
                fin: false,
                out dataBlockedFrame,
                out streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0015")]
    [Requirement("REQ-QUIC-RFC9000-S3P1-0017")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ResetStateFuzz_AbortSendsResetAndAcknowledgementEntersResetRecvd()
    {
        for (int iteration = 0; iteration < 32; iteration++)
        {
            bool bidirectional = (iteration & 1) == 0;
            int sentLength = iteration % 7;
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: 128,
                localBidirectionalSendLimit: 128,
                localUnidirectionalSendLimit: 128);

            Assert.True(state.TryOpenLocalStream(bidirectional, out QuicStreamId streamId, out QuicStreamsBlockedFrame blockedFrame));
            Assert.Equal(default, blockedFrame);

            if (sentLength > 0)
            {
                Assert.True(state.TryReserveSendCapacity(
                    streamId.Value,
                    offset: 0,
                    sentLength,
                    fin: false,
                    out _,
                    out _,
                    out QuicTransportErrorCode reserveErrorCode));
                Assert.Equal(default, reserveErrorCode);
            }

            Assert.True(state.TryAbortLocalStreamWrites(streamId.Value, out ulong finalSize, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal((ulong)sentLength, finalSize);

            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot resetSentSnapshot));
            Assert.Equal(QuicStreamSendState.ResetSent, resetSentSnapshot.SendState);
            Assert.True(resetSentSnapshot.HasFinalSize);
            Assert.Equal((ulong)sentLength, resetSentSnapshot.FinalSize);

            Assert.True(state.TryAcknowledgeSendCompletion(streamId.Value));
            Assert.True(state.TryGetStreamSnapshot(streamId.Value, out QuicConnectionStreamSnapshot resetRecvdSnapshot));
            Assert.Equal(QuicStreamSendState.ResetRecvd, resetRecvdSnapshot.SendState);
            Assert.Equal((ulong)sentLength, resetRecvdSnapshot.FinalSize);
            Assert.False(state.TryAcknowledgeSendCompletion(streamId.Value));
        }
    }
}
