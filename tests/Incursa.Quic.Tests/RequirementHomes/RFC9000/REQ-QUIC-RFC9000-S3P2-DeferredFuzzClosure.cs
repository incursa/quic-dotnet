// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S3P2_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0007")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0009")]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0010")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReorderedPeerSendControlFuzz_OpensBidirectionalStreamsBeforeDataArrives()
    {
        Random random = new(0x53_02_0007);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            ulong streamId = 1UL + (ulong)(4 * (iteration % 8));
            ulong advertisedSendLimit = 257UL + (ulong)random.Next(0, 96);
            ulong applicationErrorCode = (ulong)random.Next(0, 1 << 16);
            byte[] streamData = RandomBytes(random, random.Next(1, 8));
            QuicConnectionStreamState creditFirstState = CreatePeerBidirectionalStreamState();
            QuicConnectionStreamState stopSendingFirstState = CreatePeerBidirectionalStreamState();

            Assert.True(creditFirstState.TryApplyMaxStreamDataFrame(
                new QuicMaxStreamDataFrame(streamId, advertisedSendLimit),
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(creditFirstState.TryReceiveStreamDataBlockedFrame(
                new QuicStreamDataBlockedFrame(streamId, advertisedSendLimit),
                out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(creditFirstState.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot creditSnapshot));
            Assert.Equal(QuicStreamType.Bidirectional, creditSnapshot.StreamType);
            Assert.Equal(QuicStreamSendState.Ready, creditSnapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.Recv, creditSnapshot.ReceiveState);
            Assert.Equal(advertisedSendLimit, creditSnapshot.SendLimit);

            Assert.True(stopSendingFirstState.TryReceiveStopSendingFrame(
                new QuicStopSendingFrame(streamId, applicationErrorCode),
                out QuicResetStreamFrame resetStreamFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.Equal(streamId, resetStreamFrame.StreamId);
            Assert.Equal(applicationErrorCode, resetStreamFrame.ApplicationProtocolErrorCode);
            Assert.Equal(0UL, resetStreamFrame.FinalSize);

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0A, streamId, streamData),
                out QuicStreamFrame streamFrame));
            Assert.True(stopSendingFirstState.TryReceiveStreamFrame(streamFrame, out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(stopSendingFirstState.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot stopSnapshot));
            Assert.Equal(QuicStreamType.Bidirectional, stopSnapshot.StreamType);
            Assert.Equal(QuicStreamSendState.ResetSent, stopSnapshot.SendState);
            Assert.Equal(QuicStreamReceiveState.Recv, stopSnapshot.ReceiveState);
            Assert.Equal((ulong)streamData.Length, stopSnapshot.UniqueBytesReceived);
            Assert.Equal(streamData.Length, stopSnapshot.BufferedReadableBytes);
            Assert.True(stopSnapshot.HasFinalSize);
            Assert.Equal(0UL, stopSnapshot.FinalSize);
            Assert.True(stopSnapshot.HasSendAbortErrorCode);
            Assert.Equal(applicationErrorCode, stopSnapshot.SendAbortErrorCode);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S3P2-0021")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void ReceiveResetFuzz_EntersResetRecvdFromRecvAndSizeKnownStates()
    {
        Random random = new(0x53_02_0021);

        for (int iteration = 0; iteration < 64; iteration++)
        {
            ulong streamId = 1UL + (ulong)(4 * (iteration % 8));
            int prefixLength = random.Next(1, 8);
            int tailLength = random.Next(1, 8);
            ulong finalSize = (ulong)(prefixLength + tailLength);
            ulong applicationErrorCode = (ulong)random.Next(0, 1 << 16);
            QuicConnectionStreamState recvState = CreatePeerBidirectionalStreamState();
            QuicConnectionStreamState sizeKnownState = CreatePeerBidirectionalStreamState();

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0A, streamId, RandomBytes(random, prefixLength), offset: 0),
                out QuicStreamFrame recvFrame));
            Assert.True(recvState.TryReceiveStreamFrame(recvFrame, out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(recvState.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId, applicationErrorCode, finalSize),
                out QuicMaxDataFrame maxDataFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(maxDataFrame.MaximumData >= finalSize);

            Assert.True(recvState.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot recvSnapshot));
            Assert.Equal(QuicStreamReceiveState.ResetRecvd, recvSnapshot.ReceiveState);
            Assert.True(recvSnapshot.HasFinalSize);
            Assert.Equal(finalSize, recvSnapshot.FinalSize);
            Assert.Equal(0, recvSnapshot.BufferedReadableBytes);
            Assert.True(recvSnapshot.HasReceiveAbortErrorCode);
            Assert.Equal(applicationErrorCode, recvSnapshot.ReceiveAbortErrorCode);

            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(
                    0x0F,
                    streamId,
                    RandomBytes(random, tailLength),
                    offset: (ulong)prefixLength),
                out QuicStreamFrame sizeKnownFrame));
            Assert.True(sizeKnownState.TryReceiveStreamFrame(sizeKnownFrame, out errorCode));
            Assert.Equal(default, errorCode);

            Assert.True(sizeKnownState.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot preResetSnapshot));
            Assert.Equal(QuicStreamReceiveState.SizeKnown, preResetSnapshot.ReceiveState);
            Assert.True(preResetSnapshot.HasFinalSize);
            Assert.Equal(finalSize, preResetSnapshot.FinalSize);

            Assert.True(sizeKnownState.TryReceiveResetStreamFrame(
                new QuicResetStreamFrame(streamId, applicationErrorCode, finalSize),
                out maxDataFrame,
                out errorCode));
            Assert.Equal(default, errorCode);
            Assert.True(maxDataFrame.MaximumData >= finalSize);

            Assert.True(sizeKnownState.TryGetStreamSnapshot(streamId, out QuicConnectionStreamSnapshot sizeKnownSnapshot));
            Assert.Equal(QuicStreamReceiveState.ResetRecvd, sizeKnownSnapshot.ReceiveState);
            Assert.True(sizeKnownSnapshot.HasFinalSize);
            Assert.Equal(finalSize, sizeKnownSnapshot.FinalSize);
            Assert.Equal(0, sizeKnownSnapshot.BufferedReadableBytes);
        }
    }

    private static QuicConnectionStreamState CreatePeerBidirectionalStreamState()
    {
        return QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 256,
            connectionSendLimit: 256,
            incomingBidirectionalStreamLimit: 1024,
            incomingUnidirectionalStreamLimit: 1024,
            peerBidirectionalStreamLimit: 1024,
            peerUnidirectionalStreamLimit: 1024,
            peerBidirectionalReceiveLimit: 256,
            peerUnidirectionalReceiveLimit: 256,
            localBidirectionalReceiveLimit: 256,
            localUnidirectionalSendLimit: 256,
            peerBidirectionalSendLimit: 256);
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }
}
