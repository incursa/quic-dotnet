// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

public sealed class QuicStandaloneFinSchedulingTests
{
    [Fact]
    public async Task ApplicationSendTimer_SendsStandaloneFinAfterCongestionClears()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] request = [0xD1];
        await stream.WriteAsync(request, 0, request.Length);
        QuicConnectionTransitionResult payloadTimerResult = ExpireApplicationSendTimer(runtime);
        Assert.Single(payloadTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        outboundEffects.Clear();

        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        if (congestion.BytesInFlightBytes < congestion.CongestionWindowBytes)
        {
            congestion.RegisterPacketSent(congestion.CongestionWindowBytes - congestion.BytesInFlightBytes);
        }

        Assert.False(congestion.CanSend(1));

        await stream.CompleteWritesAsync().AsTask();
        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicConnectionTransitionResult blockedTimerResult = ExpireApplicationSendTimer(runtime);
        Assert.Empty(blockedTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        congestion.Reset();
        QuicConnectionTransitionResult finTimerResult = ExpireApplicationSendTimer(runtime);

        QuicConnectionSendDatagramEffect finSendEffect = Assert.Single(
            finTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] packetPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            runtime,
            finSendEffect);
        ReadOnlySpan<byte> unpaddedPayload = SkipPadding(packetPayload);

        Assert.True(QuicStreamParser.TryParseStreamFrame(unpaddedPayload, out QuicStreamFrame finFrame));
        Assert.Equal((ulong)stream.Id, finFrame.StreamId.Value);
        Assert.Equal((ulong)request.Length, finFrame.Offset);
        Assert.True(finFrame.IsFin);
        Assert.Equal(0, finFrame.StreamDataLength);
        Assert.True(SkipPadding(unpaddedPayload[finFrame.ConsumedLength..]).IsEmpty);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    [Fact]
    public async Task ApplicationSendTimer_RetainsStandaloneFinWhenPositiveBudgetCannotFitHeader()
    {
        using QuicConnectionRuntime runtime =
            QuicS13ApplicationSendDelayTestSupport.CreateFinishedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        byte[] request = [0xD1];
        await stream.WriteAsync(request, 0, request.Length);
        QuicConnectionTransitionResult payloadTimerResult = ExpireApplicationSendTimer(runtime);
        Assert.Single(payloadTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        outboundEffects.Clear();

        QuicCongestionControlState congestion = runtime.SendRuntime.FlowController.CongestionControlState;
        ulong remainingBudget = congestion.CongestionWindowBytes - congestion.BytesInFlightBytes;
        Assert.True(remainingBudget > 1);
        congestion.RegisterPacketSent(remainingBudget - 1);

        Assert.True(congestion.CanSend(1));
        Assert.False(congestion.CanSend(2));

        await stream.CompleteWritesAsync().AsTask();
        Assert.Empty(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());

        QuicConnectionTransitionResult blockedTimerResult = ExpireApplicationSendTimer(runtime);
        Assert.Empty(blockedTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        Assert.NotNull(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));

        congestion.Reset();
        QuicConnectionTransitionResult finTimerResult = ExpireApplicationSendTimer(runtime);

        QuicConnectionSendDatagramEffect finSendEffect = Assert.Single(
            finTimerResult.Effects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] packetPayload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(
            runtime,
            finSendEffect);
        ReadOnlySpan<byte> unpaddedPayload = SkipPadding(packetPayload);

        Assert.True(QuicStreamParser.TryParseStreamFrame(unpaddedPayload, out QuicStreamFrame finFrame));
        Assert.Equal((ulong)stream.Id, finFrame.StreamId.Value);
        Assert.Equal((ulong)request.Length, finFrame.Offset);
        Assert.True(finFrame.IsFin);
        Assert.Equal(0, finFrame.StreamDataLength);
        Assert.True(SkipPadding(unpaddedPayload[finFrame.ConsumedLength..]).IsEmpty);
        Assert.Null(runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay));
    }

    private static QuicConnectionTransitionResult ExpireApplicationSendTimer(QuicConnectionRuntime runtime)
    {
        long? dueTicks = runtime.TimerState.GetDueTicks(QuicConnectionTimerKind.ApplicationSendDelay);
        Assert.NotNull(dueTicks);
        ulong generation = runtime.TimerState.GetGeneration(QuicConnectionTimerKind.ApplicationSendDelay);

        return runtime.Transition(
            new QuicConnectionTimerExpiredEvent(
                dueTicks.Value,
                QuicConnectionTimerKind.ApplicationSendDelay,
                generation),
            nowTicks: dueTicks.Value);
    }

    private static ReadOnlySpan<byte> SkipPadding(ReadOnlySpan<byte> payload)
    {
        int index = 0;
        while (index < payload.Length && payload[index] == 0)
        {
            index++;
        }

        return payload[index..];
    }
}
