// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Text;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="workbench quality sync">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S13-0002">A sender MAY wait for a short period of time to collect multiple frames before sending a packet that is not maximally packed, to avoid sending out large numbers of small packets.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S13-0002")]
public sealed class REQ_QUIC_RFC9000_S13_0002
{
    private static readonly byte[] PacketConnectionId =
    [
        0x0A, 0x0B, 0x0C,
    ];

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_CoalescesMultipleSmallWritesAfterTheSendDelayExpires()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);

        byte[] firstPayload = [0xA1];
        byte[] secondPayload = [0xB2];

        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);

        bool sawQueuedStreamFrame = false;
        foreach (QuicConnectionSendDatagramEffect queuedSendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator queuedApplicationCoordinator = new(PacketConnectionId);
            if (!queuedApplicationCoordinator.TryOpenProtectedApplicationDataPacket(
                queuedSendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] queuedOpenedPacket,
                out int queuedPayloadOffset,
                out int queuedPayloadLength,
                out bool queuedKeyPhase))
            {
                continue;
            }

            Assert.False(queuedKeyPhase);
            ReadOnlySpan<byte> packetPayload = queuedOpenedPacket.AsSpan(queuedPayloadOffset, queuedPayloadLength);
            if (QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == 0UL
                && frame.StreamData.SequenceEqual(firstPayload))
            {
                sawQueuedStreamFrame = true;
                break;
            }
        }

        Assert.False(sawQueuedStreamFrame);

        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);
        bool sawQueuedStreamFrameAfterSecondWrite = false;
        foreach (QuicConnectionSendDatagramEffect secondWriteSendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator secondWriteCoordinator = new(PacketConnectionId);
            if (!secondWriteCoordinator.TryOpenProtectedApplicationDataPacket(
                secondWriteSendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] secondWriteOpenedPacket,
                out int secondWritePayloadOffset,
                out int secondWritePayloadLength,
                out bool secondWriteKeyPhase))
            {
                continue;
            }

            Assert.False(secondWriteKeyPhase);
            ReadOnlySpan<byte> packetPayload = secondWriteOpenedPacket.AsSpan(secondWritePayloadOffset, secondWritePayloadLength);
            if (QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == (ulong)firstPayload.Length
                && frame.StreamData.SequenceEqual(secondPayload))
            {
                sawQueuedStreamFrameAfterSecondWrite = true;
                break;
            }
        }

        Assert.False(sawQueuedStreamFrameAfterSecondWrite);

        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame firstFrame));
        Assert.Equal((ulong)stream.Id, firstFrame.StreamId.Value);
        Assert.Equal(0UL, firstFrame.Offset);
        Assert.True(firstFrame.StreamData.SequenceEqual(firstPayload));

        ReadOnlySpan<byte> remainder = SkipPadding(payload[firstFrame.ConsumedLength..]);
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainder, out QuicStreamFrame secondFrame));
        Assert.Equal((ulong)stream.Id, secondFrame.StreamId.Value);
        Assert.Equal((ulong)firstPayload.Length, secondFrame.Offset);
        Assert.True(secondFrame.StreamData.SequenceEqual(secondPayload));

        ReadOnlySpan<byte> tail = SkipPadding(remainder[secondFrame.ConsumedLength..]);
        Assert.True(tail.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ApplicationSendDelayFlushesQueuedWritesInDatagramBoundedBatches()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 64 * 1024,
            localBidirectionalSendLimit: 64 * 1024);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();

        byte[] firstPayload = [0xA1];
        byte[] secondPayload = Enumerable.Repeat((byte)0xB2, 1024).ToArray();
        byte[] thirdPayload = Enumerable.Repeat((byte)0xC3, 1024).ToArray();

        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);
        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);
        await stream.WriteAsync(thirdPayload, 0, thirdPayload.Length);

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        long? firstDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(firstDueTicks);
        ulong firstGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        QuicConnectionTransitionResult firstTimerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                firstDueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                firstGeneration),
            nowTicks: firstDueTicks.Value);

        QuicConnectionSendDatagramEffect firstBatch = Assert.Single(
            firstTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True((ulong)firstBatch.Datagram.Length <= runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        byte[] firstBatchPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, firstBatch);
        ReadOnlySpan<byte> remainingFirstBatch = SkipPadding(firstBatchPayload);

        Assert.True(QuicStreamParser.TryParseStreamFrame(remainingFirstBatch, out QuicStreamFrame firstFrame));
        Assert.Equal(0UL, firstFrame.Offset);
        Assert.True(firstFrame.StreamData.SequenceEqual(firstPayload));
        remainingFirstBatch = SkipPadding(remainingFirstBatch[firstFrame.ConsumedLength..]);

        Assert.True(QuicStreamParser.TryParseStreamFrame(remainingFirstBatch, out QuicStreamFrame secondFrame));
        Assert.Equal((ulong)firstPayload.Length, secondFrame.Offset);
        Assert.True(secondFrame.StreamData.SequenceEqual(secondPayload));
        Assert.True(SkipPadding(remainingFirstBatch[secondFrame.ConsumedLength..]).IsEmpty);

        long? secondDueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(secondDueTicks);
        ulong secondGeneration = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        QuicConnectionTransitionResult secondTimerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                secondDueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                secondGeneration),
            nowTicks: secondDueTicks.Value);

        QuicConnectionSendDatagramEffect secondBatch = Assert.Single(
            secondTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.True((ulong)secondBatch.Datagram.Length <= runtime.ActivePath.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes);
        byte[] secondBatchPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, secondBatch);
        ReadOnlySpan<byte> remainingSecondBatch = SkipPadding(secondBatchPayload);
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainingSecondBatch, out QuicStreamFrame thirdFrame));
        Assert.Equal((ulong)(firstPayload.Length + secondPayload.Length), thirdFrame.Offset);
        Assert.True(thirdFrame.StreamData.SequenceEqual(thirdPayload));
        Assert.True(SkipPadding(remainingSecondBatch[thirdFrame.ConsumedLength..]).IsEmpty);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WriteAsync_FollowedImmediatelyByCompleteWritesAsync_CoalescesTheRequestAndFinIntoOneQueuedPacket(bool handshakeConfirmed)
    {
        // Modeled from the preserved 2026-04-20 client->quic-go handshake repro:
        // the request line "GET /tired-full-diary\r\n" arrived on its own packet, and the
        // standalone FIN-only follow-up packet was the remaining interop suspect. This proof
        // keeps the request queued long enough for CompleteWritesAsync() to set FIN on that
        // same STREAM frame before the delayed flush sends it.
        QuicConnectionRuntime runtime = handshakeConfirmed
            ? QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath()
            : QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();

        byte[] request = Encoding.ASCII.GetBytes("GET /tired-full-diary\r\n");
        await stream.WriteAsync(request, 0, request.Length);

        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        await stream.CompleteWritesAsync().AsTask();

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame requestFrame));
        Assert.Equal((ulong)stream.Id, requestFrame.StreamId.Value);
        Assert.Equal(0UL, requestFrame.Offset);
        Assert.True(requestFrame.IsFin);
        Assert.True(requestFrame.StreamData.SequenceEqual(request));

        ReadOnlySpan<byte> tail = SkipPadding(payload[requestFrame.ConsumedLength..]);
        Assert.True(tail.IsEmpty);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_FollowedByCompleteWritesAsync_PreservesQueuedFinalStreamWhenCongestionBlocksImmediateFlush()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        if (congestion.BytesInFlightBytes < congestion.CongestionWindowBytes)
        {
            congestion.RegisterPacketSent(congestion.CongestionWindowBytes - congestion.BytesInFlightBytes);
        }

        Assert.False(congestion.CanSend(1));

        byte[] request = Encoding.ASCII.GetBytes("GET /queued-final\r\n");
        await stream.WriteAsync(request, 0, request.Length);

        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        await stream.CompleteWritesAsync().AsTask();

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        congestion.Reset();
        QuicConnectionTransitionResult timerResult = runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                ObservedAtTicks: dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            timerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> payload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(payload, out QuicStreamFrame requestFrame));
        Assert.Equal((ulong)stream.Id, requestFrame.StreamId.Value);
        Assert.Equal(0UL, requestFrame.Offset);
        Assert.True(requestFrame.IsFin);
        Assert.True(requestFrame.StreamData.SequenceEqual(request));

        ReadOnlySpan<byte> tail = SkipPadding(payload[requestFrame.ConsumedLength..]);
        Assert.True(tail.IsEmpty);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReceivingAckFlushesQueuedApplicationSendAfterRecoveryProgress()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();

        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        if (congestion.BytesInFlightBytes < congestion.CongestionWindowBytes)
        {
            congestion.RegisterPacketSent(congestion.CongestionWindowBytes - congestion.BytesInFlightBytes);
        }

        Assert.False(congestion.CanSend(1));

        byte[] payload = [0xD1];
        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        QuicConnectionTransitionResult ackResult = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1,
            largestAcknowledged: openPacket.Key.PacketNumber);

        QuicConnectionSendDatagramEffect queuedSendEffect = Assert.Single(
            ackResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] openedPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, queuedSendEffect);
        ReadOnlySpan<byte> packetPayload = SkipPadding(openedPayload);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame));
        Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
        Assert.Equal(0UL, frame.Offset);
        Assert.True(frame.StreamData.SequenceEqual(payload));
        Assert.True(SkipPadding(packetPayload[frame.ConsumedLength..]).IsEmpty);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReceivingAckFlushesQueuedApplicationSendsInDatagramBoundedBatchesAfterRecoveryProgress()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 64 * 1024,
            localBidirectionalSendLimit: 64 * 1024);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();

        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        ulong fillerPacketNumber = 100UL;
        ulong fillerBytes = congestion.CongestionWindowBytes - congestion.BytesInFlightBytes;
        runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
            QuicPacketNumberSpace.ApplicationData,
            fillerPacketNumber,
            fillerBytes,
            SentAtMicros: 1));

        Assert.False(congestion.CanSend(1));

        byte[] firstPayload = [0xD1];
        byte[] secondPayload = Enumerable.Repeat((byte)0xD2, 1024).ToArray();
        byte[] thirdPayload = Enumerable.Repeat((byte)0xD3, 1024).ToArray();
        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);
        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);
        await stream.WriteAsync(thirdPayload, 0, thirdPayload.Length);

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        QuicConnectionTransitionResult ackResult = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1,
            largestAcknowledged: fillerPacketNumber);

        QuicConnectionSendDatagramEffect[] queuedSendEffects =
            ackResult.Effects.OfType<QuicConnectionSendDatagramEffect>().ToArray();
        Assert.True(queuedSendEffects.Length > 1);
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> firstQueuedPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, queuedSendEffects[0].Datagram);
        Assert.Equal(openPacket.Key.PacketNumber + 1, firstQueuedPacket.Key.PacketNumber);

        List<(ulong Offset, byte[] Data)> observedFrames = [];
        foreach (QuicConnectionSendDatagramEffect queuedSendEffect in queuedSendEffects)
        {
            byte[] batchPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
                runtime,
                queuedSendEffect);
            ReadOnlySpan<byte> remainingBatch = SkipPadding(batchPayload);
            while (!remainingBatch.IsEmpty)
            {
                Assert.True(QuicStreamParser.TryParseStreamFrame(remainingBatch, out QuicStreamFrame frame));
                Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
                if (!frame.StreamData.IsEmpty)
                {
                    observedFrames.Add((frame.Offset, frame.StreamData.ToArray()));
                }

                remainingBatch = SkipPadding(remainingBatch[frame.ConsumedLength..]);
            }
        }

        Assert.Collection(
            observedFrames,
            frame =>
            {
                Assert.Equal(0UL, frame.Offset);
                Assert.True(frame.Data.SequenceEqual(firstPayload));
            },
            frame =>
            {
                Assert.Equal((ulong)firstPayload.Length, frame.Offset);
                Assert.True(frame.Data.SequenceEqual(secondPayload));
            },
            frame =>
            {
                Assert.Equal((ulong)(firstPayload.Length + secondPayload.Length), frame.Offset);
                Assert.True(frame.Data.SequenceEqual(thirdPayload));
            });
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task ReceivingAckFlushesQueuedApplicationSendsOnlyWithinAvailableCongestionBudget()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath(
            connectionSendLimit: 64 * 1024,
            localBidirectionalSendLimit: 64 * 1024);
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();
        Assert.True(runtime.SendRuntime.TryDiscardPacketNumberSpace(
            QuicPacketNumberSpace.ApplicationData,
            discardAckGenerationState: false));

        ulong acknowledgedFillerPacketNumber = FillCongestionWindowWithTrackedPackets(runtime);
        Assert.False(runtime.SendRuntime.FlowController.CongestionControlState.CanSend(1));

        byte[] firstPayload = Enumerable.Repeat((byte)0xD1, 1024).ToArray();
        byte[] secondPayload = Enumerable.Repeat((byte)0xD2, 1024).ToArray();
        byte[] thirdPayload = Enumerable.Repeat((byte)0xD3, 1024).ToArray();
        await stream.WriteAsync(firstPayload, 0, firstPayload.Length);
        await stream.WriteAsync(secondPayload, 0, secondPayload.Length);
        await stream.WriteAsync(thirdPayload, 0, thirdPayload.Length);

        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        QuicConnectionTransitionResult ackResult = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1,
            largestAcknowledged: acknowledgedFillerPacketNumber);

        QuicConnectionSendDatagramEffect queuedSendEffect = Assert.Single(
            ackResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] openedPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, queuedSendEffect);
        ReadOnlySpan<byte> remainingPayload = SkipPadding(openedPayload);
        Assert.True(QuicStreamParser.TryParseStreamFrame(remainingPayload, out QuicStreamFrame frame));
        Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
        Assert.Equal(0UL, frame.Offset);
        Assert.False(frame.StreamData.IsEmpty);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task ReceivingAckWithoutQueuedApplicationSendDoesNotEmitApplicationData()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicConnectionSendDatagramEffect openSendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        KeyValuePair<QuicConnectionSentPacketKey, QuicConnectionSentPacket> openPacket =
            QuicS13AckPiggybackTestSupport.FindTrackedPacket(runtime, openSendEffect.Datagram);
        outboundEffects.Clear();

        QuicConnectionTransitionResult ackResult = QuicS13AckPiggybackTestSupport.ReceiveOneRttAckOnly(
            runtime,
            observedAtTicks: 10,
            packetNumber: 1,
            largestAcknowledged: openPacket.Key.PacketNumber);

        Assert.Empty(ackResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    private static ulong FillCongestionWindowWithTrackedPackets(QuicConnectionRuntime runtime)
    {
        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        ulong packetBytes = runtime.ActivePath!.Value.MaximumDatagramSizeState.MaximumDatagramSizeBytes;
        ulong packetNumber = 100;
        ulong acknowledgedPacketNumber = packetNumber;

        while (congestion.BytesInFlightBytes < congestion.CongestionWindowBytes)
        {
            ulong remainingBytes = congestion.CongestionWindowBytes - congestion.BytesInFlightBytes;
            ulong payloadBytes = Math.Min(packetBytes, remainingBytes);
            runtime.SendRuntime.TrackSentPacket(new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                packetNumber++,
                payloadBytes,
                SentAtMicros: 1));
        }

        return acknowledgedPacketNumber;
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAsync_DoesNotSendTheQueuedPacketBeforeTheDelayExpires()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();
        Assert.True(runtime.ActivePath.HasValue);
        Assert.Equal(new QuicConnectionPathIdentity("203.0.113.11", RemotePort: 443), runtime.ActivePath!.Value.Identity);
        Assert.True(runtime.ActivePath.Value.AmplificationState.IsAddressValidated);

        byte[] payload = [0xCC];
        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.Contains(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);

        bool sawQueuedStreamFrame = false;
        foreach (QuicConnectionSendDatagramEffect queuedSendEffect in outboundEffects.OfType<QuicConnectionSendDatagramEffect>())
        {
            QuicHandshakeFlowCoordinator queuedApplicationCoordinator = new(PacketConnectionId);
            if (!queuedApplicationCoordinator.TryOpenProtectedApplicationDataPacket(
                queuedSendEffect.Datagram.Span,
                runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
                out byte[] queuedOpenedPacket,
                out int queuedPayloadOffset,
                out int queuedPayloadLength,
                out bool queuedKeyPhase))
            {
                continue;
            }

            Assert.False(queuedKeyPhase);
            ReadOnlySpan<byte> packetPayload = queuedOpenedPacket.AsSpan(queuedPayloadOffset, queuedPayloadLength);
            if (QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame)
                && frame.StreamId.Value == (ulong)stream.Id
                && frame.Offset == 0UL
                && frame.StreamData.SequenceEqual(payload))
            {
                sawQueuedStreamFrame = true;
                break;
            }
        }

        Assert.False(sawQueuedStreamFrame);
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task WriteAsync_AtSmallPacketDelayThresholdSendsWithoutDelay()
    {
        QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        Assert.True(runtime.ActivePath.HasValue);
        runtime.Transition(
            new QuicConnectionPacketReceivedEvent(
                ObservedAtTicks: 9,
                runtime.ActivePath.Value.Identity,
                new byte[QuicVersionNegotiation.Version1MinimumDatagramPayloadSize]),
            nowTicks: 9);
        outboundEffects.Clear();

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] payload = Enumerable.Range(0, 32).Select(index => (byte)(0x40 + index)).ToArray();
        await stream.WriteAsync(payload, 0, payload.Length);

        Assert.DoesNotContain(outboundEffects, effect =>
            effect is QuicConnectionArmTimerEffect arm
            && arm.TimerKind == QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        QuicHandshakeFlowCoordinator coordinator = new(PacketConnectionId);
        Assert.True(coordinator.TryOpenProtectedApplicationDataPacket(
            sendEffect.Datagram.Span,
            runtime.TlsState.OneRttProtectPacketProtectionMaterial!.Value,
            out byte[] openedPacket,
            out int payloadOffset,
            out int payloadLength,
            out bool keyPhase));
        Assert.False(keyPhase);

        ReadOnlySpan<byte> packetPayload = openedPacket.AsSpan(payloadOffset, payloadLength);
        Assert.True(QuicStreamParser.TryParseStreamFrame(packetPayload, out QuicStreamFrame frame));
        Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
        Assert.Equal(0UL, frame.Offset);
        Assert.True(frame.StreamData.SequenceEqual(payload));

        ReadOnlySpan<byte> tail = SkipPadding(packetPayload[frame.ConsumedLength..]);
        Assert.True(tail.IsEmpty);
    }

    private static ReadOnlySpan<byte> SkipPadding(ReadOnlySpan<byte> payload)
    {
        while (!payload.IsEmpty)
        {
            if (payload[0] != 0x00)
            {
                return payload;
            }

            Assert.True(QuicFrameCodec.TryParsePaddingFrame(payload, out int paddingBytesConsumed));
            Assert.Equal(1, paddingBytesConsumed);
            payload = payload[paddingBytesConsumed..];
        }

        return payload;
    }
}
