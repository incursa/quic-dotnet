namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P3-0003">A QUIC implementation SHOULD use information provided by the application to determine how to allocate resources to active streams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P3-0003")]
public sealed class REQ_QUIC_RFC9000_S2P3_0003
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P3-0003")]
    [Requirement("REQ-QUIC-RFC9000-0022")]
    [CoverageType(RequirementCoverageType.Positive)]
    [CoverageType(RequirementCoverageType.Edge)]
    [Trait("Category", "Positive")]
    [Trait("Category", "Edge")]
    public async Task EqualPriorityQueuedWritesPreserveFirstInFirstOutOrder()
    {
        var runtimeBundle = QuicS2P3PriorityTestSupport.CreateRuntimeWithTransitionCapture();
        await using QuicConnectionRuntime runtime = runtimeBundle.Runtime;
        await using QuicStream firstStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await using QuicStream secondStream = await runtime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        firstStream.Priority = 0;
        secondStream.Priority = 0;

        byte[] firstPayload = [0x31, 0x32, 0x33];
        byte[] secondPayload = [0x41, 0x42, 0x43];

        await firstStream.WriteAsync(firstPayload, 0, firstPayload.Length, CancellationToken.None);
        await secondStream.WriteAsync(secondPayload, 0, secondPayload.Length, CancellationToken.None);

        await secondStream.CompleteWritesAsync();

        QuicConnectionTransitionResult flushTransition = runtimeBundle.Transitions
            .Last(transition => transition.Effects.Any(effect => effect is QuicConnectionSendDatagramEffect));

        QuicConnectionSendDatagramEffect sendEffect = flushTransition.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Single();

        ReadOnlyMemory<byte> openedPayload = QuicS2P3PriorityTestSupport.OpenProtectedApplicationPayload(
            runtime,
            sendEffect.Datagram);

        Assert.Equal(
            new[] { checked((ulong)firstStream.Id), checked((ulong)secondStream.Id) },
            QuicS2P3PriorityTestSupport.ReadStreamFrameIds(openedPayload.Span));
    }
}
