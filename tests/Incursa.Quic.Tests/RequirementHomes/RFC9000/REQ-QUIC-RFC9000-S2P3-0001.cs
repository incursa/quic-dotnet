namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-S2P3-0001">QUIC MUST NOT provide a mechanism for exchanging prioritization information.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-S2P3-0001")]
public sealed class REQ_QUIC_RFC9000_S2P3_0001
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-S2P3-0001")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public async Task LocalPriorityOnlyDoesNotChangeTheOpenedApplicationPayload()
    {
        var first = QuicS2P3PriorityTestSupport.CreateRuntimeWithTransitionCapture();
        var second = QuicS2P3PriorityTestSupport.CreateRuntimeWithTransitionCapture();

        await using QuicConnectionRuntime firstRuntime = first.Runtime;
        await using QuicConnectionRuntime secondRuntime = second.Runtime;
        await using QuicStream firstStream = await firstRuntime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);
        await using QuicStream secondStream = await secondRuntime.OpenOutboundStreamAsync(QuicStreamType.Bidirectional);

        firstStream.Priority = 0;
        secondStream.Priority = 99;

        byte[] payload = [0x10, 0x20, 0x30];

        await firstStream.WriteAsync(payload, 0, payload.Length, CancellationToken.None);
        await firstStream.CompleteWritesAsync();

        await secondStream.WriteAsync(payload, 0, payload.Length, CancellationToken.None);
        await secondStream.CompleteWritesAsync();

        QuicConnectionTransitionResult firstFlushTransition = first.Transitions
            .Last(transition => transition.Effects.Any(effect => effect is QuicConnectionSendDatagramEffect));

        QuicConnectionSendDatagramEffect firstSend = firstFlushTransition.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Single();

        QuicConnectionTransitionResult secondFlushTransition = second.Transitions
            .Last(transition => transition.Effects.Any(effect => effect is QuicConnectionSendDatagramEffect));

        QuicConnectionSendDatagramEffect secondSend = secondFlushTransition.Effects
            .OfType<QuicConnectionSendDatagramEffect>()
            .Single();

        ReadOnlyMemory<byte> firstPayload = QuicS2P3PriorityTestSupport.OpenProtectedApplicationPayload(
            firstRuntime,
            firstSend.Datagram);
        ReadOnlyMemory<byte> secondPayload = QuicS2P3PriorityTestSupport.OpenProtectedApplicationPayload(
            secondRuntime,
            secondSend.Datagram);

        Assert.Equal(firstPayload.ToArray(), secondPayload.ToArray());
        Assert.Equal(
            new[] { checked((ulong)firstStream.Id) },
            QuicS2P3PriorityTestSupport.ReadStreamFrameIds(firstPayload.Span));
        Assert.Equal(
            new[] { checked((ulong)secondStream.Id) },
            QuicS2P3PriorityTestSupport.ReadStreamFrameIds(secondPayload.Span));
    }
}
