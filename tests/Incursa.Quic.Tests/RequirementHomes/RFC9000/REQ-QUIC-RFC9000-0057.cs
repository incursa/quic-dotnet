// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Tests;

/// <workbench-requirements generated="true" source="manual">
///   <workbench-requirement requirementId="REQ-QUIC-RFC9000-0057">A QUIC implementation SHOULD provide ways in which an application can indicate the relative priority of streams.</workbench-requirement>
/// </workbench-requirements>
[Requirement("REQ-QUIC-RFC9000-0057")]
public sealed class REQ_QUIC_RFC9000_0057
{
    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0057")]
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
    [Requirement("REQ-QUIC-RFC9000-0057")]
    [Requirement("REQ-QUIC-RFC9000-0022")]
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

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0057")]
    [CoverageType(RequirementCoverageType.Negative)]
    [Trait("Category", "Negative")]
    public void QueuedPrioritySelection_DoesNotLetLowerPriorityOvertakeHigherPriority()
    {
        QuicApplicationSendQueue sendQueue = new();

        sendQueue.Enqueue(streamId: 1, priority: 0, streamPayload: [0x11], streamPayloadLength: 1);
        sendQueue.Enqueue(streamId: 5, priority: 10, streamPayload: [0x22], streamPayloadLength: 1);

        PendingApplicationSendRequest[] sortedWrites = sendQueue.RentSortedQueuedWrites(out int queuedWriteCount);
        try
        {
            ReadOnlySpan<PendingApplicationSendRequest> selectedWrites = sortedWrites.AsSpan(0, queuedWriteCount);

            Assert.Equal(5UL, selectedWrites[0].StreamId);
            Assert.NotEqual(1UL, selectedWrites[0].StreamId);
        }
        finally
        {
            QuicApplicationSendQueue.ReturnRentedQueuedWrites(sortedWrites);
        }
    }

    [Fact]
    [Requirement("REQ-QUIC-RFC9000-0057")]
    [CoverageType(RequirementCoverageType.Fuzz)]
    [Trait("Category", "Fuzz")]
    public void QueuedPrioritySelection_FuzzOrdersQueuedWritesByDescendingPriority()
    {
        for (int priorityOffset = -3; priorityOffset <= 3; priorityOffset++)
        {
            QuicApplicationSendQueue sendQueue = new();
            sendQueue.Enqueue(streamId: 1, priority: priorityOffset, streamPayload: [0x11], streamPayloadLength: 1);
            sendQueue.Enqueue(streamId: 5, priority: priorityOffset + 4, streamPayload: [0x22], streamPayloadLength: 1);
            sendQueue.Enqueue(streamId: 9, priority: priorityOffset + 2, streamPayload: [0x33], streamPayloadLength: 1);

            PendingApplicationSendRequest[] sortedWrites = sendQueue.RentSortedQueuedWrites(out int queuedWriteCount);
            try
            {
                ReadOnlySpan<PendingApplicationSendRequest> selectedWrites = sortedWrites.AsSpan(0, queuedWriteCount);

                Assert.Equal(3, selectedWrites.Length);
                Assert.Equal(5UL, selectedWrites[0].StreamId);
                Assert.Equal(9UL, selectedWrites[1].StreamId);
                Assert.Equal(1UL, selectedWrites[2].StreamId);
            }
            finally
            {
                QuicApplicationSendQueue.ReturnRentedQueuedWrites(sortedWrites);
            }
        }
    }
}
