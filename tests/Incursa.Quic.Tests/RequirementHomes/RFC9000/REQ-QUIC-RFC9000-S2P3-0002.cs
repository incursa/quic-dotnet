namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P3-0002">A QUIC implementation SHOULD provide ways in which an application can indicate the relative priority of streams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P3-0002")]
public sealed class REQ_QUIC_RFC9000_S2P3_0002
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P3-0002")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task WritableStreamsExposeRoundTrippableLocalPriority()
    {
        var runtimeBundle = QuicS2P3PriorityTestSupport.CreateRuntimeWithTransitionCapture();
        await using QuicConnectionRuntime runtime = runtimeBundle.Runtime;
        await using QuicStream stream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        Assert.Equal(0, stream.Priority);

        stream.Priority = 7;

        Assert.Equal(7, stream.Priority);
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P3-0002")]
    [Requirement("REQ-QUIC-RFC9000-S2-0005")]
    [CoverageType(RequirementCoverageType.Positive)]
    [Trait("Category", "Positive")]
    public async Task HigherPriorityQueuedWritesFlushBeforeLowerPriorityQueuedWrites()
    {
        var runtimeBundle = QuicS2P3PriorityTestSupport.CreateRuntimeWithTransitionCapture();
        await using QuicConnectionRuntime runtime = runtimeBundle.Runtime;
        await using QuicStream lowerPriorityStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await using QuicStream higherPriorityStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        lowerPriorityStream.Priority = 0;
        higherPriorityStream.Priority = 10;

        byte[] lowerPayload = [0x11, 0x12, 0x13];
        byte[] higherPayload = [0x21, 0x22, 0x23];

        await lowerPriorityStream.WriteAsync(lowerPayload, 0, lowerPayload.Length, CancellationToken.None);
        await higherPriorityStream.WriteAsync(higherPayload, 0, higherPayload.Length, CancellationToken.None);

        await higherPriorityStream.CompleteWritesAsync();

        QuicConnectionTransitionResult flushTransition = runtimeBundle.Transitions
            .Last(transition => transition.Effects.Any(effect => effect is QuicConnectionSendDatagramEffect));

        QuicConnectionSendDatagramEffect sendEffect = flushTransition.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Single();

        ReadOnlyMemory<byte> openedPayload = QuicS2P3PriorityTestSupport.OpenProtectedApplicationPayload(
            runtime,
            sendEffect.Datagram);

        Assert.Equal(
            new[] { checked((ulong)higherPriorityStream.Id), checked((ulong)lowerPriorityStream.Id) },
            QuicS2P3PriorityTestSupport.ReadStreamFrameIds(openedPayload.Span));
    }
}
