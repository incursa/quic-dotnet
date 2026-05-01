namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0013">A request to cancel stream transmission, as encoded in a STOP_SENDING frame, MUST be sent until the receiving part of the stream enters either a Data Recvd state or a Reset Recvd state.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0013")]
public sealed class REQ_QUIC_RFC9000_S13P3_0013
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0013")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task StopSendingActionRetainsTheProtectedPacketUntilAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);
        outboundEffects.Clear();

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> stopSendingPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength));

        Assert.True(QuicStreamControlFrameTestSupport.TryFindStopSendingFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicStopSendingFrame stopSendingFrame,
            out _,
            out _));
        Assert.Equal(0UL, stopSendingFrame.StreamId);
        Assert.Equal(0x99UL, stopSendingFrame.ApplicationProtocolErrorCode);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            stopSendingPacket.Key.PacketNumberSpace,
            stopSendingPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Key.PacketNumber == stopSendingPacket.Key.PacketNumber);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0013")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task StopSendingRetransmissionStaysQueuedWhenAnUnrelatedPacketIsAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);
        outboundEffects.Clear();

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> stopSendingPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            stopSendingPacket.Key.PacketNumberSpace,
            stopSendingPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.False(runtime.SendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            stopSendingPacket.Key.PacketNumber + 1,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0013")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task StopSendingRetransmissionIsSuppressedWhenReceivePartReachesDataRecvd()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);
        outboundEffects.Clear();

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> stopSendingPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            stopSendingPacket.Key.PacketNumberSpace,
            stopSendingPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        _ = ReceiveProtectedApplicationPayload(
            runtime,
            QuicStreamTestData.BuildStreamFrame(0x0F, streamId: (ulong)stream.Id, streamData: [0x44], offset: 0));

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            streamIdValue: (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.DataRecvd, snapshot.ReceiveState);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0013")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task StopSendingRetransmissionIsSuppressedWhenResetStreamArrives()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);
        outboundEffects.Clear();

        await runtime.AbortStreamReadsAsync((ulong)stream.Id, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> stopSendingPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            stopSendingPacket.Key.PacketNumberSpace,
            stopSendingPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        _ = ReceiveProtectedApplicationPayload(
            runtime,
            BuildResetStreamPayload(new QuicResetStreamFrame(
                streamId: (ulong)stream.Id,
                applicationProtocolErrorCode: 0x44,
                finalSize: 0)));

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            streamIdValue: (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.ResetRead, snapshot.ReceiveState);
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    private static QuicConnectionTransitionResult ReceiveProtectedApplicationPayload(
        QuicConnectionRuntime runtime,
        ReadOnlySpan<byte> payload)
    {
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryBuildProtectedApplicationDataPacket(
            payload,
            runtime.TlsState.OneRttOpenPacketProtectionMaterial!.Value,
            out byte[] protectedPacket));

        Assert.NotNull(runtime.ActivePath);
        return runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 1,
                runtime.ActivePath.Value.Identity,
                protectedPacket),
            nowTicks: 1);
    }

    private static byte[] BuildResetStreamPayload(QuicResetStreamFrame frame)
    {
        byte[] payload = new byte[64];
        Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(frame, payload, out int bytesWritten));
        Assert.True(bytesWritten > 0);
        if (bytesWritten < payload.Length)
        {
            payload.AsSpan(bytesWritten).Fill(0);
        }

        return payload;
    }
}
