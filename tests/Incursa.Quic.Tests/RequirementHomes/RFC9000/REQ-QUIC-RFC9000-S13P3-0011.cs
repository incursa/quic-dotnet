namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0011">Cancellation of stream transmission, as carried in a RESET_STREAM frame, MUST be sent until acknowledged or until all stream data is acknowledged by the peer.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0011")]
public sealed class REQ_QUIC_RFC9000_S13P3_0011
{
    private static readonly byte[] PacketConnectionId = [0x0A, 0x0B, 0x0C];

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0011")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ResetStreamActionRetainsTheProtectedPacketUntilAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await runtime.AbortStreamWritesAsync(0, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> resetPacket = Assert.Single(
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

        Assert.True(QuicStreamControlFrameTestSupport.TryFindResetStreamFrame(
            openedPacket.AsSpan(payloadOffset, payloadLength),
            out QuicResetStreamFrame resetStreamFrame,
            out _,
            out _));
        Assert.Equal(0UL, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);
        Assert.Equal(0UL, resetStreamFrame.FinalSize);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.DoesNotContain(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Key.PacketNumber == resetPacket.Key.PacketNumber);
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0011")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ResetStreamRetransmissionStaysQueuedWhenAnUnrelatedPacketIsAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await runtime.AbortStreamWritesAsync(0, 0x99);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> resetPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.False(runtime.SendRuntime.TryAcknowledgePacket(
            QuicPacketNumberSpace.ApplicationData,
            resetPacket.Key.PacketNumber + 1,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.True(retransmission.PacketBytes.Span.SequenceEqual(sendEffect.Datagram.Span));
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0011")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task ResetStreamRetransmissionWaitsUntilAllStreamDataIsAcknowledged()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 96,
            localBidirectionalSendLimit: 96);
        List<QuicConnectionEffect> outboundEffects = [];
        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        AcknowledgeTrackedPackets(runtime);

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.Equal(0L, stream.Id);
        AcknowledgeTrackedPackets(runtime);
        outboundEffects.Clear();

        byte[] firstPayload = new byte[32];
        firstPayload.AsSpan().Fill(0x33);
        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);

        QuicConnectionSendDatagramEffect firstStreamSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> firstStreamPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(firstStreamSendEffect.Datagram.Span));

        outboundEffects.Clear();

        byte[] secondPayload = new byte[32];
        secondPayload.AsSpan().Fill(0x44);
        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);

        QuicConnectionSendDatagramEffect secondStreamSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> secondStreamPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Value.PacketBytes.Span.SequenceEqual(secondStreamSendEffect.Datagram.Span));

        outboundEffects.Clear();
        await runtime.AbortStreamWritesAsync((ulong)stream.Id, 0x99);

        QuicConnectionSendDatagramEffect resetSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> resetPacket = Assert.Single(
            runtime.SendRuntime.SentPackets,
            entry => entry.Key.PacketNumberSpace == QuicPacketNumberSpace.ApplicationData
                && entry.Value.PacketBytes.Span.SequenceEqual(resetSendEffect.Datagram.Span));

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            resetPacket.Key.PacketNumberSpace,
            resetPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            firstStreamPacket.Key.PacketNumberSpace,
            firstStreamPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        Assert.True(runtime.SendRuntime.TryAcknowledgePacket(
            secondStreamPacket.Key.PacketNumberSpace,
            secondStreamPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);
        Assert.False(runtime.SendRuntime.TryDequeueRetransmission(out _));
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
}
