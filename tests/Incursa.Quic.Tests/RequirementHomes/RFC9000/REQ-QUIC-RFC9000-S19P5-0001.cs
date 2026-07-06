// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0001")]
public sealed class REQ_QUIC_RFC9000_S19P5_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0001")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortRead_EmitsStopSendingType05ForDiscardedIncomingData()
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

        stream.Abort(QuicAbortDirection.Read, 0x66);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);
        Assert.Equal(0x66UL, stopSendingFrame.ApplicationProtocolErrorCode);

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0001")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public async Task AbortRead_FuzzEmitsStopSendingType05ForDiscardedIncomingData()
    {
        long[] applicationErrorCodes = [0, 1, 0x66, 0x3FFF];

        foreach (long applicationErrorCode in applicationErrorCodes)
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

            stream.Abort(QuicAbortDirection.Read, applicationErrorCode);

            Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
                runtime,
                outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
                out QuicStopSendingFrame stopSendingFrame));
            Assert.Equal((ulong)stream.Id, stopSendingFrame.StreamId);
            Assert.Equal((ulong)applicationErrorCode, stopSendingFrame.ApplicationProtocolErrorCode);

            await stream.DisposeAsync();
        }
    }
}
