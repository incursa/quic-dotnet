using System.Linq;

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P4-0004">On the supported active runtime path, a writable stream MAY end cleanly by sending a STREAM frame with the FIN bit set, and a post-FIN write MUST be rejected as already completed.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P4-0004")]
public sealed class REQ_QUIC_RFC9000_S2P4_0004
{
    [Fact]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task CompleteWrites_OnTheSupportedRuntimePath_EmitsAFinOnlyStreamFrame()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        Assert.True(stream.CanWrite);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.False(stream.CanWrite);

        QuicConnectionSendDatagramEffect sendEffect = Assert.Single(outboundEffects.OfType<QuicConnectionSendDatagramEffect>());
        byte[] payload = QuicS13AckPiggybackTestSupport.OpenOutgoingApplicationPayload(runtime, sendEffect);
        QuicStreamFrame frame = QuicS13RetransmissionTestSupport.AssertSingleStreamFrame(payload);

        Assert.Equal((ulong)stream.Id, frame.StreamId.Value);
        Assert.Equal(0UL, frame.Offset);
        Assert.Equal(0, frame.StreamDataLength);
        Assert.True(frame.IsFin);
    }

    [Fact]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task WriteAfterCompleteWrites_OnTheSupportedRuntimePath_IsRejectedWithAnInvalidOperationException()
    {
        using QuicConnectionRuntime runtime = QuicS13ApplicationSendDelayTestSupport.CreateConfirmedClientRuntimeWithValidatedActivePath();
        List<QuicConnectionEffect> outboundEffects = [];

        runtime.SetLocalApiEventDispatcher(connectionEvent =>
        {
            QuicConnectionTransitionResult transition = runtime.Transition(connectionEvent);
            outboundEffects.AddRange(transition.Effects);
            return true;
        });

        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        outboundEffects.Clear();

        await stream.CompleteWritesAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(5));
        await stream.WritesClosed.WaitAsync(TimeSpan.FromSeconds(5));
        outboundEffects.Clear();

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => stream.WriteAsync(new byte[] { 0x01 }, 0, 1));

        Assert.Equal("The writable side is already completed.", exception.Message);
        Assert.False(stream.CanWrite);
        Assert.Empty(outboundEffects);
    }
}
