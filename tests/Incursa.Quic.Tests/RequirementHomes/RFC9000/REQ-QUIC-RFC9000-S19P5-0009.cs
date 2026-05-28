// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
public sealed class REQ_QUIC_RFC9000_S19P5_0009
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public void TryParseStopSendingFrame_PreservesIgnoredStreamId()
    {
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(
            new QuicStopSendingFrame(streamId: 0x44, applicationProtocolErrorCode: 0x55));

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out _));
        Assert.Equal(0x44UL, parsed.StreamId);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task AbortRead_StopsOnlyTheNamedStream()
    {
        using QuicConnectionRuntime runtime = QuicPostHandshakeTicketTestSupport.CreateFinishedClientRuntime();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        QuicStream targetStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        QuicStream unrelatedStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        targetStream.Abort(QuicAbortDirection.Read, 0x66);

        Assert.True(QuicStreamControlFrameTestSupport.TryFindProtectedStopSendingFrame(
            runtime,
            outboundEffects.OfType<QuicConnectionSendDatagramEffect>(),
            out QuicStopSendingFrame stopSendingFrame));
        Assert.Equal((ulong)targetStream.Id, stopSendingFrame.StreamId);
        Assert.True(unrelatedStream.CanRead);

        await unrelatedStream.DisposeAsync();
        await targetStream.DisposeAsync();
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P5-0009")]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Edge")]
    public void TryParseStopSendingFrame_PreservesMaximumEncodedStreamId()
    {
        byte[] encoded = QuicFrameTestData.BuildStopSendingFrame(
            new QuicStopSendingFrame(
                QuicVariableLengthInteger.MaxValue,
                applicationProtocolErrorCode: 0x55));

        Assert.True(QuicFrameCodec.TryParseStopSendingFrame(encoded, out QuicStopSendingFrame parsed, out int bytesConsumed));
        Assert.Equal(encoded.Length, bytesConsumed);
        Assert.Equal(QuicVariableLengthInteger.MaxValue, parsed.StreamId);
    }
}
