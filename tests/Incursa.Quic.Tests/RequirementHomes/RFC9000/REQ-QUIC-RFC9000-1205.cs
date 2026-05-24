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
}
