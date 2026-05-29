// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks pending retransmission queue removal paths used by ACK processing and key discard.
/// </summary>
[MemoryDiagnoser]
public class QuicRetransmissionQueueRemovalBenchmarks
{
    private QuicRetransmissionQueue queue = new();
    private QuicConnectionSentPacketKey acknowledgedPacketKey;

    /// <summary>
    /// Gets or sets the number of pending retransmission plans queued before the removal operation.
    /// </summary>
    [Params(8, 128, 512)]
    public int PendingRetransmissionCount { get; set; }

    /// <summary>
    /// Prepares a queue where the ACK removes one matching packet from the middle of the queue.
    /// </summary>
    [IterationSetup(Target = nameof(RemoveAcknowledgedApplicationPacketFromMiddle))]
    public void SetupAcknowledgedApplicationPacket()
    {
        queue = CreateQueue();
        acknowledgedPacketKey = new QuicConnectionSentPacketKey(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)(PendingRetransmissionCount / 2));
    }

    /// <summary>
    /// Prepares a queue where old one-RTT key-phase discard removes half of the queued plans.
    /// </summary>
    [IterationSetup(Target = nameof(DiscardOldOneRttKeyPhase))]
    public void SetupOldOneRttKeyPhase()
    {
        queue = CreateQueue();
    }

    /// <summary>
    /// Prepares a queue where age-based discard removes the older half of the queued plans.
    /// </summary>
    [IterationSetup(Target = nameof(DiscardOlderPendingRetransmissions))]
    public void SetupOlderPendingRetransmissions()
    {
        queue = CreateQueue();
    }

    /// <summary>
    /// Measures the ACK-processing removal of a single pending retransmission.
    /// </summary>
    [Benchmark]
    public int RemoveAcknowledgedApplicationPacketFromMiddle()
    {
        return queue.TryRemovePendingRetransmission(acknowledgedPacketKey) ? queue.Count : -1;
    }

    /// <summary>
    /// Measures discarding all pending retransmissions protected with an old one-RTT key phase.
    /// </summary>
    [Benchmark]
    public int DiscardOldOneRttKeyPhase()
    {
        return queue.TryDiscardOneRttKeyPhase(keyPhase: 0) ? queue.Count : -1;
    }

    /// <summary>
    /// Measures discarding pending retransmissions sent before the selected time boundary.
    /// </summary>
    [Benchmark]
    public int DiscardOlderPendingRetransmissions()
    {
        return queue.TryDiscardPendingRetransmissionsOlderThan((ulong)(PendingRetransmissionCount / 2)) ? queue.Count : -1;
    }

    private QuicRetransmissionQueue CreateQueue()
    {
        QuicRetransmissionQueue retransmissionQueue = new();
        for (int index = 0; index < PendingRetransmissionCount; index++)
        {
            retransmissionQueue.QueueRetransmission(CreatePlan(index));
        }

        return retransmissionQueue;
    }

    private static QuicConnectionRetransmissionPlan CreatePlan(int index)
    {
        return new QuicConnectionRetransmissionPlan(
            QuicPacketNumberSpace.ApplicationData,
            (ulong)index,
            PayloadBytes: 1_200,
            SentAtMicros: (ulong)index,
            PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
            OneRttKeyPhase: (ulong)(index & 1));
    }
}
