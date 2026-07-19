// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Measures the contiguous packet-receipt path used by sustained raw QUIC transfers.
/// </summary>
[MemoryDiagnoser]
public class QuicAckGenerationStateRecordingBenchmarks
{
    private QuicAckGenerationState pendingAfterRetainedHistory = null!;

    /// <summary>
    /// Gets or sets the number of contiguous packet receipts recorded per operation.
    /// </summary>
    [Params(128, 1_024, 2_400)]
    public int ReceiptCount { get; set; }

    /// <summary>
    /// Builds retained history with one newer packet pending after the last ACK trigger.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        pendingAfterRetainedHistory = new QuicAckGenerationState();
        for (int index = 0; index < ReceiptCount; index++)
        {
            pendingAfterRetainedHistory.RecordProcessedPacket(
                QuicPacketNumberSpace.ApplicationData,
                (ulong)index,
                ackEliciting: true,
                receivedAtMicros: (ulong)index);
        }

        pendingAfterRetainedHistory.MarkAckFrameSent(
            QuicPacketNumberSpace.ApplicationData,
            sentAtMicros: (ulong)ReceiptCount,
            ackOnlyPacket: false);
        pendingAfterRetainedHistory.RecordProcessedPacket(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)ReceiptCount,
            ackEliciting: true,
            receivedAtMicros: (ulong)ReceiptCount);
    }

    /// <summary>
    /// Returns pooled receipt storage used by the retained-history benchmark.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        pendingAfterRetainedHistory.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData);
    }

    /// <summary>
    /// Records one contiguous application-data range and builds its ACK frame.
    /// </summary>
    [Benchmark]
    public int RecordContiguousAckElicitingPackets()
    {
        QuicAckGenerationState state = new();
        try
        {
            for (int index = 0; index < ReceiptCount; index++)
            {
                state.RecordProcessedPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    (ulong)index,
                    ackEliciting: true,
                    receivedAtMicros: (ulong)index);
            }

            if (!state.TryBuildAckFrame(
                    QuicPacketNumberSpace.ApplicationData,
                    nowMicros: (ulong)ReceiptCount,
                    out QuicAckFrame frame))
            {
                return -1;
            }

            using (frame)
            {
                return state.MaximumRetainedAckRanges
                    ^ unchecked((int)frame.LargestAcknowledged)
                    ^ unchecked((int)frame.FirstAckRange);
            }
        }
        finally
        {
            state.TryDiscardPacketNumberSpace(QuicPacketNumberSpace.ApplicationData);
        }
    }

    /// <summary>
    /// Checks one pending packet after a large acknowledged-but-not-yet-retired prefix.
    /// </summary>
    [Benchmark]
    public bool CheckPendingAckAfterRetainedHistory()
    {
        return pendingAfterRetainedHistory.ShouldIncludeAckFrameWithOutgoingPacket(
            QuicPacketNumberSpace.ApplicationData,
            nowMicros: (ulong)ReceiptCount,
            maxAckDelayMicros: 25_000);
    }
}
