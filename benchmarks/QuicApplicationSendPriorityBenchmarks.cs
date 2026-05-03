using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks the delayed application-send queue ordering used by the runtime when queued stream writes are flushed.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationSendPriorityBenchmarks
{
    private QuicConnectionRuntime.PendingApplicationSendRequest[] mixedPriorityQueuedWrites = [];
    private QuicConnectionRuntime.PendingApplicationSendRequest[] equalPriorityQueuedWrites = [];

    /// <summary>
    /// Prepares representative queued writes with mixed priorities and equal-priority FIFO tie cases.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        mixedPriorityQueuedWrites =
        [
            new QuicConnectionRuntime.PendingApplicationSendRequest(0, 11, 0, [0x11, 0x12, 0x13]),
            new QuicConnectionRuntime.PendingApplicationSendRequest(1, 13, 10, [0x21, 0x22, 0x23]),
            new QuicConnectionRuntime.PendingApplicationSendRequest(2, 15, 5, [0x31, 0x32, 0x33]),
            new QuicConnectionRuntime.PendingApplicationSendRequest(3, 17, 10, [0x41, 0x42, 0x43]),
        ];

        equalPriorityQueuedWrites =
        [
            new QuicConnectionRuntime.PendingApplicationSendRequest(0, 21, 7, [0x51, 0x52]),
            new QuicConnectionRuntime.PendingApplicationSendRequest(1, 23, 7, [0x61, 0x62]),
            new QuicConnectionRuntime.PendingApplicationSendRequest(2, 25, 7, [0x71, 0x72]),
            new QuicConnectionRuntime.PendingApplicationSendRequest(3, 27, 7, [0x81, 0x82]),
        ];
    }

    /// <summary>
    /// Measures ordering the delayed send queue when priorities differ.
    /// </summary>
    [Benchmark]
    public ulong SortQueuedApplicationSendsByPriorityThenSequence()
    {
        QuicConnectionRuntime.PendingApplicationSendRequest[] queuedWrites =
            (QuicConnectionRuntime.PendingApplicationSendRequest[])mixedPriorityQueuedWrites.Clone();

        Array.Sort(queuedWrites, QuicConnectionRuntime.ComparePendingApplicationSendRequests);
        return queuedWrites[0].StreamId ^ queuedWrites[^1].StreamId;
    }

    /// <summary>
    /// Measures ordering the delayed send queue when priorities are equal and FIFO becomes the tiebreaker.
    /// </summary>
    [Benchmark]
    public ulong SortQueuedApplicationSendsWithEqualPriorityPreservesFifoOrder()
    {
        QuicConnectionRuntime.PendingApplicationSendRequest[] queuedWrites =
            (QuicConnectionRuntime.PendingApplicationSendRequest[])equalPriorityQueuedWrites.Clone();

        Array.Sort(queuedWrites, QuicConnectionRuntime.ComparePendingApplicationSendRequests);
        return (ulong)queuedWrites[0].Sequence + (ulong)queuedWrites[^1].Sequence;
    }
}
