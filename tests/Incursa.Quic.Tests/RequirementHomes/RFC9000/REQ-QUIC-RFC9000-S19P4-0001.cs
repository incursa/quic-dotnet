namespace Incursa.Quic.Tests;

[Requirement("REQ-QUIC-RFC9000-S19P4-0001")]
public sealed class REQ_QUIC_RFC9000_S19P4_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S19P4-0001")]
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
}
