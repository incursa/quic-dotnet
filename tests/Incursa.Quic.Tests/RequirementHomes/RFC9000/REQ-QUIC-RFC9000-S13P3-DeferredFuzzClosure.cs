// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class REQ_QUIC_RFC9000_S13P3_DeferredFuzzClosure
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0005")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0009")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0011")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0013")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task Fuzz_StreamRetransmissionAndCancellationRepairLifecycle()
    {
        QuicS13StreamDataSend streamSend = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime streamRuntime = streamSend.Runtime;

        Assert.True(streamRuntime.SendRuntime.TryRegisterLoss(
            streamSend.PacketKey.PacketNumberSpace,
            streamSend.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, streamRuntime.SendRuntime.PendingRetransmissionCount);
        Assert.True(streamRuntime.SendRuntime.TryAcknowledgePacket(
            streamSend.PacketKey.PacketNumberSpace,
            streamSend.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(0, streamRuntime.SendRuntime.PendingRetransmissionCount);
        Assert.False(streamRuntime.SendRuntime.TryDequeueRetransmission(out _));

        QuicS13StreamDataSend resetSuppressedSend = await QuicS13RetransmissionTestSupport.SendSingleStreamDataPacketAsync();
        using QuicConnectionRuntime resetSuppressedRuntime = resetSuppressedSend.Runtime;
        Assert.True(resetSuppressedRuntime.SendRuntime.TryRegisterLoss(
            resetSuppressedSend.PacketKey.PacketNumberSpace,
            resetSuppressedSend.PacketKey.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, resetSuppressedRuntime.SendRuntime.PendingRetransmissionCount);

        await resetSuppressedRuntime.AbortStreamWritesAsync(resetSuppressedSend.StreamFrame.StreamId, applicationErrorCode: 0x99);

        Assert.Equal(0, resetSuppressedRuntime.SendRuntime.PendingRetransmissionCount);
        Assert.False(resetSuppressedRuntime.SendRuntime.TryDequeueRetransmission(out _));

        foreach ((byte[] packet, ulong packetNumber) in new[]
        {
            (QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(0, 0x44, 0)), 21UL),
            (QuicFrameTestData.BuildStopSendingFrame(new QuicStopSendingFrame(0, 0x55)), 22UL),
        })
        {
            QuicConnectionSendRuntime sendRuntime = new();
            TrackRepairPacket(sendRuntime, packet, packetNumber, sentAtMicros: 1_000 + packetNumber);

            Assert.True(sendRuntime.TryRegisterLoss(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                handshakeConfirmed: true));
            Assert.Equal(1, sendRuntime.PendingRetransmissionCount);
            Assert.True(sendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
            Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
            sendRuntime.QueueRetransmission(retransmission);

            Assert.True(sendRuntime.TryAcknowledgePacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber,
                handshakeConfirmed: true));
            Assert.Equal(0, sendRuntime.PendingRetransmissionCount);
            Assert.False(sendRuntime.TryDequeueRetransmission(out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0007")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_CryptoRetransmissionDataIsDiscardedWithPacketNumberSpaceKeys()
    {
        foreach ((QuicPacketNumberSpace space, QuicTlsEncryptionLevel level, ulong packetNumber, byte seed) in new[]
        {
            (QuicPacketNumberSpace.Initial, QuicTlsEncryptionLevel.Initial, 1UL, (byte)0x10),
            (QuicPacketNumberSpace.Handshake, QuicTlsEncryptionLevel.Handshake, 2UL, (byte)0x20),
        })
        {
            QuicConnectionSendRuntime sendRuntime = new();
            TrackCryptoPacket(sendRuntime, space, level, packetNumber, seed);

            Assert.True(sendRuntime.TryRegisterLoss(space, packetNumber, handshakeConfirmed: space == QuicPacketNumberSpace.Handshake));
            Assert.Equal(1, sendRuntime.PendingRetransmissionCount);
            Assert.True(sendRuntime.TryDiscardPacketNumberSpace(space));

            Assert.DoesNotContain(sendRuntime.SentPackets.Keys, key => key.PacketNumberSpace == space);
            Assert.Equal(0, sendRuntime.PendingRetransmissionCount);
            Assert.False(sendRuntime.TryDequeueRetransmission(out _));
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0021")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0024")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_FlowControlCreditAndBlockedRepairFramesAcrossLimits()
    {
        foreach ((ulong receiveLimit, ulong initialStreamLimit, byte firstByte, int readLength) in new[]
        {
            (16UL, 8UL, (byte)0x10, 2),
            (32UL, 12UL, (byte)0x20, 3),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionReceiveLimit: receiveLimit,
                peerBidirectionalReceiveLimit: initialStreamLimit);
            byte[] streamData = CreateSequentialBytes(firstByte, readLength);
            Assert.True(QuicStreamParser.TryParseStreamFrame(
                QuicStreamTestData.BuildStreamFrame(0x0E, 1, streamData, offset: 0),
                out QuicStreamFrame frame));
            Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

            byte[] destination = new byte[readLength];
            Assert.True(state.TryReadStreamData(
                1,
                destination,
                out int bytesWritten,
                out bool completed,
                out _,
                out QuicMaxStreamDataFrame maxStreamDataFrame,
                out errorCode));

            Assert.Equal(default, errorCode);
            Assert.Equal(readLength, bytesWritten);
            Assert.False(completed);
            Assert.Equal(1UL, maxStreamDataFrame.StreamId);
            Assert.Equal(initialStreamLimit + (ulong)readLength, maxStreamDataFrame.MaximumStreamData);

            AssertRepairQueuesUntilAcknowledged(
                QuicFrameTestData.BuildMaxStreamDataFrame(maxStreamDataFrame),
                packetNumber: 30UL + (ulong)readLength);
        }

        foreach (bool bidirectional in new[] { false, true })
        {
            byte[] maxStreamsPacket = QuicFrameTestData.BuildMaxStreamsFrame(new QuicMaxStreamsFrame(bidirectional, 2));
            Assert.True(QuicFrameCodec.TryParseMaxStreamsFrame(maxStreamsPacket, out QuicMaxStreamsFrame maxStreamsFrame, out int bytesConsumed));
            Assert.Equal(maxStreamsPacket.Length, bytesConsumed);
            Assert.Equal(bidirectional, maxStreamsFrame.IsBidirectional);
            AssertRepairQueuesUntilAcknowledged(maxStreamsPacket, packetNumber: bidirectional ? 42UL : 41UL);
        }

        foreach ((ulong connectionSendLimit, ulong streamSendLimit, int length) in new[]
        {
            (1UL, 8UL, 2),
            (32UL, 1UL, 2),
        })
        {
            QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
                connectionSendLimit: connectionSendLimit,
                localBidirectionalSendLimit: streamSendLimit);
            Assert.True(state.TryOpenLocalStream(
                bidirectional: true,
                out QuicStreamId streamId,
                out QuicStreamsBlockedFrame streamsBlockedFrame));
            Assert.Equal(default, streamsBlockedFrame);
            Assert.False(state.TryReserveSendCapacity(
                streamId.Value,
                offset: 0,
                length,
                fin: false,
                out QuicDataBlockedFrame dataBlockedFrame,
                out QuicStreamDataBlockedFrame streamDataBlockedFrame,
                out QuicTransportErrorCode errorCode));
            Assert.Equal(default, errorCode);

            byte[] blockedPacket = connectionSendLimit == 1UL
                ? QuicFrameTestData.BuildDataBlockedFrame(dataBlockedFrame)
                : QuicFrameTestData.BuildStreamDataBlockedFrame(streamDataBlockedFrame);
            AssertRepairQueuesUntilAcknowledged(blockedPacket, packetNumber: connectionSendLimit == 1UL ? 51UL : 52UL);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0029")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0030")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0031")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0038")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ConnectionIdNewTokenAndStaleRepairHandling()
    {
        foreach (byte seed in new byte[] { 0x10, 0x30, 0x50 })
        {
            byte[] connectionId = CreateSequentialBytes(seed, 4);
            byte[] token = CreateSequentialBytes((byte)(seed + 0x40), QuicStatelessReset.StatelessResetTokenLength);
            byte[] newConnectionIdPacket = QuicFrameTestData.BuildNewConnectionIdFrame(
                new QuicNewConnectionIdFrame(seed, 0, connectionId, token));
            Assert.True(QuicFrameCodec.TryParseNewConnectionIdFrame(
                newConnectionIdPacket,
                out QuicNewConnectionIdFrame parsedNewConnectionId,
                out int newConnectionIdBytesConsumed));
            Assert.Equal(newConnectionIdPacket.Length, newConnectionIdBytesConsumed);
            Assert.True(parsedNewConnectionId.ConnectionId.SequenceEqual(connectionId));
            Assert.True(parsedNewConnectionId.StatelessResetToken.SequenceEqual(token));
            AssertRepairQueuesUntilAcknowledged(newConnectionIdPacket, packetNumber: seed);

            byte[] retireConnectionIdPacket = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(seed));
            Assert.True(QuicFrameCodec.TryParseRetireConnectionIdFrame(
                retireConnectionIdPacket,
                out QuicRetireConnectionIdFrame parsedRetireConnectionId,
                out int retireConnectionIdBytesConsumed));
            Assert.Equal(retireConnectionIdPacket.Length, retireConnectionIdBytesConsumed);
            Assert.Equal((ulong)seed, parsedRetireConnectionId.SequenceNumber);
            AssertRepairQueuesUntilAcknowledged(retireConnectionIdPacket, packetNumber: (ulong)seed + 1);

            byte[] duplicateNewToken = QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame(token));
            byte[] copiedNewToken = QuicFrameTestData.BuildNewTokenFrame(new QuicNewTokenFrame(token.ToArray()));
            Assert.True(QuicFrameCodec.TryParseNewTokenFrame(duplicateNewToken, out QuicNewTokenFrame firstParsedToken, out int firstTokenBytesConsumed));
            Assert.True(QuicFrameCodec.TryParseNewTokenFrame(copiedNewToken, out QuicNewTokenFrame secondParsedToken, out int secondTokenBytesConsumed));
            Assert.Equal(duplicateNewToken.Length, firstTokenBytesConsumed);
            Assert.Equal(copiedNewToken.Length, secondTokenBytesConsumed);
            Assert.True(firstParsedToken.Token.SequenceEqual(secondParsedToken.Token));
        }

        QuicConnectionSendRuntime sendRuntime = new();
        byte[] oldPacket = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(7));
        byte[] newPacket = QuicFrameTestData.BuildRetireConnectionIdFrame(new QuicRetireConnectionIdFrame(8));
        TrackRepairPacket(sendRuntime, oldPacket, packetNumber: 70, sentAtMicros: 100);
        TrackRepairPacket(sendRuntime, newPacket, packetNumber: 71, sentAtMicros: 200);
        Assert.True(sendRuntime.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, 70, handshakeConfirmed: true));
        Assert.True(sendRuntime.TryRegisterLoss(QuicPacketNumberSpace.ApplicationData, 71, handshakeConfirmed: true));

        Assert.True(sendRuntime.TryDiscardPendingRetransmissionsOlderThan(150));

        Assert.Equal(1, sendRuntime.PendingRetransmissionCount);
        Assert.True(sendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retainedRepair));
        Assert.Equal(71UL, retainedRepair.PacketNumber);
        Assert.True(newPacket.AsSpan().SequenceEqual(retainedRepair.PacketBytes.Span));
        Assert.False(sendRuntime.TryDequeueRetransmission(out _));
    }

    private static void AssertRepairQueuesUntilAcknowledged(byte[] packet, ulong packetNumber)
    {
        QuicConnectionSendRuntime sendRuntime = new();
        TrackRepairPacket(sendRuntime, packet, packetNumber, sentAtMicros: 1_000 + packetNumber);

        Assert.True(sendRuntime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, sendRuntime.PendingRetransmissionCount);
        Assert.True(sendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(packetNumber, retransmission.PacketNumber);
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        sendRuntime.QueueRetransmission(retransmission);

        Assert.True(sendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            handshakeConfirmed: true));
        Assert.Equal(0, sendRuntime.PendingRetransmissionCount);
        Assert.False(sendRuntime.TryDequeueRetransmission(out _));
    }

    private static void TrackRepairPacket(
        QuicConnectionSendRuntime sendRuntime,
        byte[] packet,
        ulong packetNumber,
        ulong sentAtMicros)
    {
        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            packetNumber,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: sentAtMicros,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet,
            PlaintextPayload: packet));
    }

    private static void TrackCryptoPacket(
        QuicConnectionSendRuntime sendRuntime,
        QuicPacketNumberSpace packetNumberSpace,
        QuicTlsEncryptionLevel encryptionLevel,
        ulong packetNumber,
        byte cryptoSeed)
    {
        byte[] plaintextPayload = FormatCryptoPayload(
            offset: packetNumber * 8,
            CreateSequentialBytes(cryptoSeed, 3));

        sendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            packetNumberSpace,
            packetNumber,
            PayloadBytes: (ulong)plaintextPayload.Length,
            SentAtMicros: 100 + packetNumber,
            AckEliciting: true,
            CryptoMetadata: new QuicConnectionCryptoSendMetadata(encryptionLevel),
            PacketBytes: new byte[] { cryptoSeed },
            PlaintextPayload: plaintextPayload));
    }

    private static byte[] FormatCryptoPayload(ulong offset, byte[] cryptoData)
    {
        byte[] payload = new byte[32];
        Assert.True(QuicFrameCodec.TryFormatCryptoFrame(
            new QuicCryptoFrame(offset, cryptoData),
            payload,
            out int bytesWritten));
        return payload[..bytesWritten];
    }

    private static byte[] CreateSequentialBytes(byte firstValue, int length)
    {
        return Enumerable.Range(0, length).Select(value => unchecked((byte)(firstValue + value))).ToArray();
    }
}
