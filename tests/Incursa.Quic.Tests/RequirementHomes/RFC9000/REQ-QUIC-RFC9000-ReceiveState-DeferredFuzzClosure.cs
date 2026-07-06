// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_ReceiveState_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0097")]
    [Requirement("REQ-QUIC-RFC9000-0098")]
    [Requirement("REQ-QUIC-RFC9000-0110")]
    [Requirement("REQ-QUIC-RFC9000-S11P2-0004")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void PeerReceivePartCreationFuzz_CreatesRecvStateFromFirstPeerDataAndControlFrames()
    {
        for (int index = 0; index < 8; index++)
        {
            ulong bidirectionalStreamId = (ulong)(1 + (index * 4));
            ulong unidirectionalStreamId = (ulong)(3 + (index * 4));
            QuicConnectionStreamState state = CreateReceiveState();

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0E, bidirectionalStreamId, [(byte)(0x10 + index)]),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            AssertPeerReceiveSnapshot(
                state,
                bidirectionalStreamId,
                QuicStreamType.Bidirectional,
                QuicStreamSendState.Ready,
                QuicStreamReceiveState.Recv);

            Assert.True(state.TryReceiveStreamDataBlockedFrame(
                new QuicStreamDataBlockedFrame(unidirectionalStreamId, maximumStreamData: (ulong)(index + 1)),
                out errorCode));
            Assert.Equal(default, errorCode);
            AssertPeerReceiveSnapshot(
                state,
                unidirectionalStreamId,
                QuicStreamType.Unidirectional,
                QuicStreamSendState.None,
                QuicStreamReceiveState.Recv);

            ulong stopSendingStreamId = (ulong)(33 + (index * 4));
            Assert.True(state.TryReceiveStopSendingFrame(
                new QuicStopSendingFrame(stopSendingStreamId, applicationProtocolErrorCode: (ulong)(0x80 + index)),
                out QuicResetStreamFrame resetStreamFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(stopSendingStreamId, resetStreamFrame.StreamId);
            Assert.Equal(0UL, resetStreamFrame.FinalSize);
            AssertPeerReceiveSnapshot(
                state,
                stopSendingStreamId,
                QuicStreamType.Bidirectional,
                QuicStreamSendState.ResetSent,
                QuicStreamReceiveState.Recv);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0113")]
    [Requirement("REQ-QUIC-RFC9000-0115")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void DataRecvdFuzz_EntersDataRecvdOnlyAfterAllDataArrivesAndMovesAfterRead()
    {
        for (int index = 0; index < 8; index++)
        {
            ulong streamId = (ulong)(1 + (index * 4));
            byte[] head = [(byte)(0x10 + index), (byte)(0x20 + index)];
            byte[] tail = [(byte)(0x30 + index), (byte)(0x40 + index)];
            QuicConnectionStreamState state = CreateReceiveState();

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0F, streamId, tail, offset: (ulong)head.Length),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot sizeKnownSnapshot));
            Assert.Equal(QuicStreamReceiveState.SizeKnown, sizeKnownSnapshot.ReceiveState);
            Assert.True(sizeKnownSnapshot.HasFinalSize);
            Assert.Equal((ulong)(head.Length + tail.Length), sizeKnownSnapshot.FinalSize);

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0E, streamId, head, offset: 0),
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot dataRecvdSnapshot));
            Assert.Equal(QuicStreamReceiveState.DataRecvd, dataRecvdSnapshot.ReceiveState);
            Assert.Equal((ulong)(head.Length + tail.Length), dataRecvdSnapshot.UniqueBytesReceived);

            byte[] destination = new byte[head.Length + tail.Length];
            Assert.True(state.TryReadStreamData(
                streamId,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out _,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(completed);
            Assert.Equal(destination.Length, bytesWritten);
            Assert.True(head.Concat(tail).ToArray().AsSpan().SequenceEqual(destination));
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot dataReadSnapshot));
            Assert.Equal(QuicStreamReceiveState.DataRead, dataReadSnapshot.ReceiveState);
            Assert.Equal((ulong)destination.Length, dataReadSnapshot.ReadOffset);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0120")]
    [Requirement("REQ-QUIC-RFC9000-0185")]
    [Requirement("REQ-QUIC-RFC9000-0186")]
    [Requirement("REQ-QUIC-RFC9000-0194")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ResetAndFinalSizeFuzz_DiscardsReceiveDataPreservesSendDirectionAndKeepsFinalSizeImmutable()
    {
        for (int index = 0; index < 8; index++)
        {
            ulong streamId = (ulong)(1 + (index * 4));
            byte[] payload = [(byte)(0x50 + index), (byte)(0x60 + index)];
            ulong resetFinalSize = (ulong)(payload.Length + 2);
            QuicConnectionStreamState state = CreateReceiveState();

            Assert.True(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0E, streamId, payload),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(state.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId, applicationProtocolErrorCode: (ulong)(0x90 + index), finalSize: resetFinalSize),
                out QuicMaxDataFrame maxDataFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.NotEqual(default, maxDataFrame);
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot resetSnapshot));
            Assert.Equal(QuicStreamReceiveState.ResetRecvd, resetSnapshot.ReceiveState);
            Assert.Equal(QuicStreamSendState.Ready, resetSnapshot.SendState);
            Assert.True(resetSnapshot.HasFinalSize);
            Assert.Equal(resetFinalSize, resetSnapshot.FinalSize);
            Assert.Equal(0, resetSnapshot.BufferedReadableBytes);

            Assert.True(state.TryReserveSendCapacity(
                streamId,
                offset: 0,
                length: 1,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out errorCode));
            Assert.Equal(default, dataBlockedFrame);
            Assert.Equal(default, streamDataBlockedFrame);
            Assert.Equal(default, errorCode);

            Assert.False(state.TryReceiveStreamFrame(
                ParseStreamFrame(0x0E, streamId, [(byte)(0x70 + index)], offset: resetFinalSize),
                out errorCode));
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);

            Assert.False(state.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId, applicationProtocolErrorCode: (ulong)(0xA0 + index), finalSize: resetFinalSize + 1),
                out _,
                out errorCode));
            Assert.Equal(QuicTransportErrorCode.FinalSizeError, errorCode);
            Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot finalSnapshot));
            Assert.Equal(resetFinalSize, finalSnapshot.FinalSize);
        }
    }

    private static QuicConnectionStreamState CreateReceiveState()
    {
        return QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 256,
            connectionSendLimit: 256,
            incomingBidirectionalStreamLimit: 64,
            incomingUnidirectionalStreamLimit: 64,
            peerBidirectionalStreamLimit: 64,
            peerUnidirectionalStreamLimit: 64,
            peerBidirectionalReceiveLimit: 64,
            peerUnidirectionalReceiveLimit: 64,
            localBidirectionalReceiveLimit: 64,
            localUnidirectionalSendLimit: 64,
            peerBidirectionalSendLimit: 64);
    }

    private static QuicStreamFrame ParseStreamFrame(
        byte frameType,
        ulong streamId,
        ReadOnlySpan<byte> data,
        ulong offset = 0)
    {
        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(frameType, streamId, data, offset),
            out QuicStreamFrame frame));
        return frame;
    }

    private static void AssertPeerReceiveSnapshot(
        QuicConnectionStreamState state,
        ulong streamId,
        QuicStreamType expectedStreamType,
        QuicStreamSendState expectedSendState,
        QuicStreamReceiveState expectedReceiveState)
    {
        Assert.True(state.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(expectedStreamType, snapshot.StreamType);
        Assert.Equal(expectedSendState, snapshot.SendState);
        Assert.Equal(expectedReceiveState, snapshot.ReceiveState);
    }
}
