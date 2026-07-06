// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-1205")]
public sealed class REQ_QUIC_RFC9000_1205
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1205")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task AbortWrite_EmitsResetStreamType04ForAbruptSendTermination()
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

        stream.Abort(QuicAbortDirection.Write, 0x99);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedResetStreamFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicResetStreamFrame resetStreamFrame));
        Assert.Equal((ulong)stream.Id, resetStreamFrame.StreamId);
        Assert.Equal(0x99UL, resetStreamFrame.ApplicationProtocolErrorCode);

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1205")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortWrite_DoesNotEmitStopSendingForAbruptSendTermination()
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

        stream.Abort(QuicAbortDirection.Write, 0x99);

        Assert.False(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out _));

        await stream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-1205")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void Fuzz_ResetStreamFrameCarriesAbruptSendTerminationFieldsWithType04()
    {
        byte[] destination = new byte[64];
        foreach ((ulong streamId, ulong errorCode, ulong finalSize) in ResetStreamCases())
        {
            QuicResetStreamFrame frame = new(streamId, errorCode, finalSize);

            Assert.True(QuicFrameCodec.TryFormatResetStreamFrame(frame, destination, out int bytesWritten));
            Assert.Equal(0x04, destination[0]);
            Assert.True(QuicFrameCodec.TryParseResetStreamFrame(
                destination.AsSpan(0, bytesWritten),
                out QuicResetStreamFrame parsed,
                out int bytesConsumed));

            Assert.Equal(bytesWritten, bytesConsumed);
            Assert.Equal(streamId, parsed.StreamId);
            Assert.Equal(errorCode, parsed.ApplicationProtocolErrorCode);
            Assert.Equal(finalSize, parsed.FinalSize);
        }
    }

    private static IEnumerable<(ulong StreamId, ulong ErrorCode, ulong FinalSize)> ResetStreamCases()
    {
        yield return (0, 0, 0);
        yield return (4, 0x99, 1_024);
        yield return (16, 0x4000, 65_535);
        yield return (63, 0x1234_5678, 1_000_000);
    }
}
