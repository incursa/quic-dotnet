// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0002")]
public sealed class REQ_QUIC_RFC9000_S19P5_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortRead_EmitsStopSendingForRecvState()
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
        outboundEffects.Clear();

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.Recv, snapshot.ReceiveState);

        stream.Abort(QuicAbortDirection.Read, 0x55);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0002")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortRead_DoesNotEmitStopSendingAfterReset()
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
        outboundEffects.Clear();

        QuicConnectionTransitionResult resetResult = QuicStreamControlFrameTestSupport.ReceiveProtectedApplicationPayload(
            runtime,
            QuicFrameTestData.BuildResetStreamFrame(new QuicResetStreamFrame(
                (ulong)stream.Id,
                applicationProtocolErrorCode: 0x22,
                finalSize: 0)));
        Assert.True(resetResult.StateChanged);

        outboundEffects.Clear();
        stream.Abort(QuicAbortDirection.Read, 0x55);

        Assert.False(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out _));

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0002")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public async Task AbortRead_EmitsStopSendingForSizeKnownState()
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

        QuicConnectionTransitionResult streamResult = QuicStreamControlFrameTestSupport.ReceiveProtectedApplicationPayload(
            runtime,
            QuicStreamTestData.BuildStreamFrame(0x0F, (ulong)stream.Id, [], offset: 4));
        Assert.True(streamResult.StateChanged);

        Assert.True(runtime.StreamRegistry.Bookkeeping.TryGetStreamSnapshot(
            (ulong)stream.Id,
            out QuicConnectionStreamSnapshot snapshot));
        Assert.Equal(QuicStreamReceiveState.SizeKnown, snapshot.ReceiveState);

        outboundEffects.Clear();
        stream.Abort(QuicAbortDirection.Read, 0x56);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);
        Assert.Equal(0x56UL, stopSendingFrame.ApplicationProtocolErrorCode);

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0002")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void StopSendingFrameCodec_FuzzRoundTripsAllowedStopSendingFields()
    {
        QuicFrameCodecFuzzSupport.FuzzStopSendingFrame();
    }
}
