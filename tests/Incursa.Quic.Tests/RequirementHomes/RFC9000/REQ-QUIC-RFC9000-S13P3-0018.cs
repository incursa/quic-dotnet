// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0018">Like MAX_DATA, an updated value MUST be sent when the packet containing the most recent MAX_STREAM_DATA frame for a stream is lost or when the limit is updated.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
public sealed class REQ_QUIC_RFC9000_S13P3_0018
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryReadStreamData_PublishesAccumulatedStreamCreditWhenTheReceiveWindowThresholdIsReached()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4096,
            peerBidirectionalReceiveLimit: 4096);

        byte[] firstPayload = new byte[1024];
        byte[] secondPayload = new byte[1024];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, firstPayload, offset: 0),
            out QuicStreamFrame firstFrame));
        Assert.True(state.TryReceiveStreamFrame(firstFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        Span<byte> destination = stackalloc byte[1024];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: true,
            out int bytesWritten,
            out bool completed,
            out _,
            out QuicMaxStreamDataFrame firstMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1024, bytesWritten);
        Assert.False(completed);
        Assert.Equal(default, firstMaxStreamDataFrame);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, secondPayload, offset: 1024),
            out QuicStreamFrame secondFrame));
        Assert.True(state.TryReceiveStreamFrame(secondFrame, out errorCode));
        Assert.Equal(default, errorCode);

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: true,
            out bytesWritten,
            out completed,
            out _,
            out QuicMaxStreamDataFrame secondMaxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1024, bytesWritten);
        Assert.False(completed);
        Assert.Equal(1UL, secondMaxStreamDataFrame.StreamId);
        Assert.Equal(6144UL, secondMaxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(6144UL, snapshot.ReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-0167")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-0180")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-0799")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_EmitsTheCurrentMaxStreamDataAndMaxDataUpdatesAfterBytesAreConsumed()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 16)));
        QuicStream stream = await OpenSixteenStreamsAsync(runtime);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryApplyInitialReceiveLimits(4096, 4096, 4096, 4096));

        byte[] payload = new byte[2048];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, payload, offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] readBuffer = new byte[2048];
        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length);

        Assert.Equal(2048, bytesRead);
        Assert.True(readBuffer.AsSpan().SequenceEqual(payload));
        AssertFlowControlCreditEffects(outboundEffects, runtime, stream.Id, expectedMaxData: 6144, expectedMaxStreamData: 6144);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReadAsync_EmitsUpdatedMaxStreamDataAndMaxDataAfterRepeatedReads()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryApplyMaxStreamsFrame(new QuicMaxStreamsFrame(true, 16)));
        QuicStream stream = await OpenSixteenStreamsAsync(runtime);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryApplyInitialReceiveLimits(4096, 4096, 4096, 4096));

        byte[] firstPayload = new byte[1024];
        byte[] secondPayload = new byte[1024];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, firstPayload, offset: 0),
            out QuicStreamFrame firstStreamFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(firstStreamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] firstReadBuffer = new byte[1024];
        int firstBytesRead = await stream.ReadAsync(firstReadBuffer, 0, firstReadBuffer.Length);

        Assert.Equal(1024, firstBytesRead);
        Assert.True(firstReadBuffer.AsSpan().SequenceEqual(firstPayload));
        Assert.Empty(outboundEffects);

        outboundEffects.Clear();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, secondPayload, offset: 1024),
            out QuicStreamFrame secondStreamFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(secondStreamFrame, out errorCode));
        Assert.Equal(default, errorCode);

        byte[] secondReadBuffer = new byte[1024];
        int secondBytesRead = await stream.ReadAsync(secondReadBuffer, 0, secondReadBuffer.Length);

        Assert.Equal(1024, secondBytesRead);
        Assert.True(secondReadBuffer.AsSpan().SequenceEqual(secondPayload));
        AssertFlowControlCreditEffects(
            outboundEffects,
            runtime,
            stream.Id,
            expectedMaxData: 6144,
            expectedMaxStreamData: 6144);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0006")]
    [Requirement("REQ-QUIC-RFC9000-0167")]
    [Requirement("REQ-QUIC-RFC9000-S4P1-0009")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0015")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0017")]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ReadAsync_DoesNotEmitCreditUpdatesWhenNoBytesAreConsumed()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, (ulong)stream.Id, [0x11, 0x22], offset: 0),
            out QuicStreamFrame streamFrame));
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryReceiveStreamFrame(streamFrame, out QuicTransportErrorCode errorCode));
        Assert.Equal(default, errorCode);

        byte[] readBuffer = [];
        int bytesRead = await stream.ReadAsync(readBuffer, 0, readBuffer.Length);

        Assert.Equal(0, bytesRead);
        Assert.Empty(outboundEffects);
        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(0UL, snapshot.ReadOffset);
        Assert.Equal(2, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_QueuesTheMostRecentMaxStreamDataPacketForRepairUntilAcknowledged()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(packet, out QuicMaxStreamDataFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.Equal(1UL, frame.StreamId);
        Assert.Equal(10UL, frame.MaximumStreamData);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 11,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 200,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            11,
            handshakeConfirmed: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(11UL, retransmission.PacketNumber);
        Assert.True(packet.AsSpan().SequenceEqual(retransmission.PacketBytes.Span));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryAcknowledgePacket_DoesNotRetainTheMostRecentMaxStreamDataFrameForRepair()
    {
        QuicConnectionSendRuntime runtime = new();
        byte[] packet = QuicFrameTestData.BuildMaxStreamDataFrame(new QuicMaxStreamDataFrame(1, 10));
        Assert.True(QuicFrameCodec.TryParseMaxStreamDataFrame(packet, out QuicMaxStreamDataFrame frame, out int bytesConsumed));
        Assert.Equal(packet.Length, bytesConsumed);
        Assert.Equal(1UL, frame.StreamId);
        Assert.Equal(10UL, frame.MaximumStreamData);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 12,
            PayloadBytes: (ulong)packet.Length,
            SentAtMicros: 250,
            AckEliciting: true,
            Retransmittable: true,
            PacketBytes: packet));

        Assert.True(runtime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            12,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            12,
            handshakeConfirmed: true));
        Assert.False(runtime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_LeavesTheCurrentStreamDataOffsetUnchangedAtTheMaximumFlowControlLimit()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: QuicVariableLengthInteger.MaxValue,
            peerBidirectionalReceiveLimit: QuicVariableLengthInteger.MaxValue);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));
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
        Assert.Equal(default, maxDataFrame);
        Assert.Equal(default, maxStreamDataFrame);

        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicVariableLengthInteger.MaxValue, snapshot.ReceiveLimit);
        Assert.Equal(2UL, snapshot.ReadOffset);
        Assert.Equal(0, snapshot.BufferedReadableBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_PublishesCreditForAOneByteReceiveWindow()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 1,
            peerBidirectionalReceiveLimit: 1);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, [0x11], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

        Span<byte> destination = stackalloc byte[1];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(1, bytesWritten);
        Assert.False(completed);
        Assert.Equal(2UL, maxDataFrame.MaximumData);
        Assert.Equal(1UL, maxStreamDataFrame.StreamId);
        Assert.Equal(2UL, maxStreamDataFrame.MaximumStreamData);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotIncreaseStreamCreditAfterTheFinalByteIsConsumed()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4096,
            peerBidirectionalReceiveLimit: 4096);

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, [0x11, 0x22], offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

        Span<byte> destination = stackalloc byte[2];
        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: true,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(2, bytesWritten);
        Assert.True(completed);
        Assert.Equal(4098UL, maxDataFrame.MaximumData);
        Assert.Equal(default, maxStreamDataFrame);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(4096UL, snapshot.ReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TryReadStreamData_DoesNotPublishStreamCreditWhenAFinalReadReachesTheBatchThreshold()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4096,
            peerBidirectionalReceiveLimit: 4096);
        byte[] payload = new byte[2048];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0F, 1, payload, offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

        Assert.True(state.TryReadStreamData(
            1,
            payload,
            useBatchedReceiveCredit: true,
            out int bytesWritten,
            out bool completed,
            out QuicMaxDataFrame maxDataFrame,
            out QuicMaxStreamDataFrame maxStreamDataFrame,
            out errorCode));

        Assert.Equal(default, errorCode);
        Assert.Equal(payload.Length, bytesWritten);
        Assert.True(completed);
        Assert.Equal(6144UL, maxDataFrame.MaximumData);
        Assert.Equal(default, maxStreamDataFrame);
        Assert.True(state.TryGetStreamSnapshot(1, out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(4096UL, snapshot.ReceiveLimit);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_CanSwitchFromImmediateToBatchedCreditPublication()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4096,
            peerBidirectionalReceiveLimit: 4096);
        byte[] payload = new byte[2048];
        Span<byte> destination = stackalloc byte[1024];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, payload, offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: false,
            out _,
            out _,
            out QuicMaxDataFrame immediateMaxDataFrame,
            out QuicMaxStreamDataFrame immediateMaxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(5120UL, immediateMaxDataFrame.MaximumData);
        Assert.Equal(5120UL, immediateMaxStreamDataFrame.MaximumStreamData);

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: true,
            out _,
            out _,
            out QuicMaxDataFrame batchedMaxDataFrame,
            out QuicMaxStreamDataFrame batchedMaxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, batchedMaxDataFrame);
        Assert.Equal(default, batchedMaxStreamDataFrame);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0018")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryReadStreamData_FlushesAccumulatedCreditWhenSwitchingBackToImmediatePublication()
    {
        QuicConnectionStreamState state = QuicConnectionStreamStateTestHelpers.CreateState(
            connectionReceiveLimit: 4096,
            peerBidirectionalReceiveLimit: 4096);
        byte[] payload = new byte[2048];
        Span<byte> destination = stackalloc byte[1024];

        Assert.True(QuicStreamParser.TryParseStreamFrame(
            QuicStreamTestData.BuildStreamFrame(0x0E, 1, payload, offset: 0),
            out QuicStreamFrame frame));
        Assert.True(state.TryReceiveStreamFrame(frame, out QuicTransportErrorCode errorCode));

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: true,
            out _,
            out _,
            out QuicMaxDataFrame batchedMaxDataFrame,
            out QuicMaxStreamDataFrame batchedMaxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(default, batchedMaxDataFrame);
        Assert.Equal(default, batchedMaxStreamDataFrame);

        Assert.True(state.TryReadStreamData(
            1,
            destination,
            useBatchedReceiveCredit: false,
            out _,
            out _,
            out QuicMaxDataFrame immediateMaxDataFrame,
            out QuicMaxStreamDataFrame immediateMaxStreamDataFrame,
            out errorCode));
        Assert.Equal(default, errorCode);
        Assert.Equal(6144UL, immediateMaxDataFrame.MaximumData);
        Assert.Equal(6144UL, immediateMaxStreamDataFrame.MaximumStreamData);
    }

    private static void AcknowledgeTrackedPackets(QuicConnectionRuntime runtime)
    {
        foreach (KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> sentPacket in runtime.SendRuntime.SentPackets.ToArray())
        {
            Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
                sentPacket.Key.PacketNumberSpace,
                sentPacket.Key.PacketNumber,
                handshakeConfirmed: true));
        }
    }

    private static async Task<QuicStream> OpenSixteenStreamsAsync(QuicConnectionRuntime runtime)
    {
        QuicStream? firstStream = null;
        for (int streamIndex = 0; streamIndex < 16; streamIndex++)
        {
            QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
            firstStream ??= stream;
        }

        return firstStream!;
    }

    private static void AssertFlowControlCreditEffects(
        IReadOnlyCollection<QuicConnectionEffect> outboundEffects,
        QuicConnectionRuntime runtime,
        long streamId,
        ulong expectedMaxData,
        ulong expectedMaxStreamData)
    {
        Assert.InRange(outboundEffects.Count, 1, 2);

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        bool sawMaxData = false;
        bool sawMaxStreamData = false;

        foreach (QuicConnectionEffect effect in outboundEffects)
        {
            QuicConnectionSendDatagramEffect sendEffect = Assert.IsType<QuicConnectionSendDatagramEffect>(effect);
            Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
                sendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] openedPacket,
                out int payloadOffset,
                out int payloadLength));

            ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
            while (!payload.IsEmpty)
            {
                if (QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed))
                {
                    payload = payload[paddingBytesConsumed..];
                    continue;
                }

                if (QuicFrameCodec.TryParseMaxDataFrame(payload, out QuicMaxDataFrame maxDataFrame, out int maxDataBytesConsumed))
                {
                    sawMaxData = true;
                    Assert.Equal(expectedMaxData, maxDataFrame.MaximumData);
                    payload = payload[maxDataBytesConsumed..];
                    continue;
                }

                if (QuicFrameCodec.TryParseMaxStreamDataFrame(payload, out QuicMaxStreamDataFrame maxStreamDataFrame, out int maxStreamDataBytesConsumed))
                {
                    sawMaxStreamData = true;
                    Assert.Equal((ulong)streamId, maxStreamDataFrame.StreamId);
                    Assert.Equal(expectedMaxStreamData, maxStreamDataFrame.MaximumStreamData);
                    payload = payload[maxStreamDataBytesConsumed..];
                    continue;
                }

                Assert.Fail("Unexpected flow-control frame.");
            }
        }

        Assert.True(sawMaxData);
        Assert.True(sawMaxStreamData);
    }

    private static void AssertOnlyPadding(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed));
            payload = payload[paddingBytesConsumed..];
        }
    }
}
