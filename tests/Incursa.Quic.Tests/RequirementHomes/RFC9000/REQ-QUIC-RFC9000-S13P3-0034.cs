namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13P3-0034">Endpoints SHOULD prioritize retransmission of data over sending new data, unless priorities specified by the application indicate otherwise.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13P3-0034")]
public sealed class REQ_QUIC_RFC9000_S13P3_0034
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryRegisterLoss_LeavesQueuedRetransmissionsAvailableAfterLaterTrackedPackets()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 7,
            PayloadBytes: 1_200,
            SentAtMicros: 100,
            AckEliciting: true));

        Assert.True(runtime.TryRegisterLoss(
            QuicPacketNumberSpace.ApplicationData,
            7,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.PendingRetransmissionCount);

        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 125,
            AckEliciting: true));

        Assert.Equal(1, runtime.PendingRetransmissionCount);
        Assert.Single(runtime.SentPackets);
        Assert.Contains(runtime.SentPackets.Keys, key => key.PacketNumber == 8);
        Assert.True(runtime.TryDequeueRetransmission(out QuicConnectionRetransmissionPlan retransmission));
        Assert.Equal(7UL, retransmission.PacketNumber);
        Assert.Equal(1_200UL, retransmission.PayloadBytes);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S13P3-0034")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_QueuesNewStreamDataBehindPendingStreamRetransmission()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 128,
            localBidirectionalSendLimit: 128);
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

        byte[] firstPayload = new byte[32];
        firstPayload.AsSpan().Fill(0x41);
        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);

        QuicConnectionSendDatagramEffect firstSend = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> firstPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, firstSend.Datagram);

        Assert.True(runtime.SendRuntime.TryRegisterLoss(
            firstPacket.Key.PacketNumberSpace,
            firstPacket.Key.PacketNumber,
            handshakeConfirmed: true));
        Assert.Equal(1, runtime.SendRuntime.PendingRetransmissionCount);

        outboundEffects.Clear();

        byte[] secondPayload = new byte[32];
        secondPayload.AsSpan().Fill(0x52);
        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);

        QuicConnectionSendDatagramEffect retransmissionSend = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] retransmissionPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            runtime,
            retransmissionSend);
        QuicStreamFrame retransmissionFrame =
            QuicS13RetransmissionTestSupport.AssertSingleStreamFrame(retransmissionPayload);
        Assert.Equal((ulong)stream.Id, retransmissionFrame.StreamId.Value);
        Assert.Equal(0UL, retransmissionFrame.Offset);
        Assert.True(retransmissionFrame.StreamData.SequenceEqual(firstPayload));
        Assert.Equal(0, runtime.SendRuntime.PendingRetransmissionCount);

        long? delayedSendDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(delayedSendDueTicks);
        ulong delayedSendGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        QuicConnectionTransitionResult delayedSendResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: delayedSendDueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                delayedSendGeneration),
            nowTicks: delayedSendDueTicks.Value);

        QuicConnectionSendDatagramEffect delayedNewDataSend = Assert.Single(
            delayedSendResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] delayedNewDataPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            runtime,
            delayedNewDataSend);
        QuicStreamFrame delayedNewDataFrame =
            QuicS13RetransmissionTestSupport.AssertSingleStreamFrame(delayedNewDataPayload);
        Assert.Equal((ulong)stream.Id, delayedNewDataFrame.StreamId.Value);
        Assert.Equal((ulong)firstPayload.Length, delayedNewDataFrame.Offset);
        Assert.True(delayedNewDataFrame.StreamData.SequenceEqual(secondPayload));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void TrackSentPacket_DoesNotCreateRetransmissionsWithoutLoss()
    {
        QuicConnectionSendRuntime runtime = new();
        runtime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            PacketNumber: 8,
            PayloadBytes: 900,
            SentAtMicros: 125,
            AckEliciting: true));

        Assert.Single(runtime.SentPackets);
        Assert.Equal(0, runtime.PendingRetransmissionCount);
        Assert.False(runtime.TryDequeueRetransmission(out _));
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
