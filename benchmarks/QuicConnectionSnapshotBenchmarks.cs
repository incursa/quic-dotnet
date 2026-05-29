// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Buffers;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks terminal-path snapshot patterns that previously materialized arrays from dictionaries.
/// </summary>
[MemoryDiagnoser]
public class QuicConnectionSnapshotBenchmarks
{
    private readonly Dictionary<long, int> pendingStreamActionRequests = [];
    private readonly Dictionary<ulong, byte[]> statelessResetTokensByConnectionId = [];

    /// <summary>
    /// Gets or sets the number of entries in each snapshot source.
    /// </summary>
    [Params(0, 1, 8, 32)]
    public int EntryCount { get; set; }

    /// <summary>
    /// Prepares the dictionary sources for each benchmark case.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        pendingStreamActionRequests.Clear();
        statelessResetTokensByConnectionId.Clear();

        for (int index = 0; index < EntryCount; index++)
        {
            long requestId = index + 1;
            pendingStreamActionRequests.Add(requestId, index);
            statelessResetTokensByConnectionId.Add((ulong)requestId, [unchecked((byte)index)]);
        }
    }

    /// <summary>
    /// Measures the current stream-action snapshot shape that materializes a fresh array.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PendingStreamActionRequestsToArray()
    {
        KeyValuePair<long, int>[] snapshot = pendingStreamActionRequests.ToArray();
        int checksum = 0;
        for (int index = 0; index < snapshot.Length; index++)
        {
            checksum += (int)snapshot[index].Key + snapshot[index].Value;
        }

        return checksum;
    }

    /// <summary>
    /// Measures the pooled stream-action snapshot shape used by the terminal cleanup path.
    /// </summary>
    [Benchmark]
    public int PendingStreamActionRequestsPooledSnapshot()
    {
        KeyValuePair<long, int>[] rented = ArrayPool<KeyValuePair<long, int>>.Shared.Rent(pendingStreamActionRequests.Count);
        try
        {
            int count = 0;
            foreach (KeyValuePair<long, int> entry in pendingStreamActionRequests)
            {
                rented[count++] = entry;
            }

            int checksum = 0;
            for (int index = 0; index < count; index++)
            {
                checksum += (int)rented[index].Key + rented[index].Value;
            }

            return checksum;
        }
        finally
        {
            ArrayPool<KeyValuePair<long, int>>.Shared.Return(rented, clearArray: true);
        }
    }

    /// <summary>
    /// Measures the current connection-ID snapshot shape that materializes the key list.
    /// </summary>
    [Benchmark]
    public int IssuedConnectionIdsKeysToArray()
    {
        ulong[] connectionIds = statelessResetTokensByConnectionId.Keys.ToArray();
        int checksum = 0;
        for (int index = 0; index < connectionIds.Length; index++)
        {
            checksum += unchecked((int)connectionIds[index]);
        }

        return checksum;
    }

    /// <summary>
    /// Measures the pooled connection-ID snapshot shape used by terminal retirement.
    /// </summary>
    [Benchmark]
    public int IssuedConnectionIdsPooledSnapshot()
    {
        ulong[] rented = ArrayPool<ulong>.Shared.Rent(statelessResetTokensByConnectionId.Count);
        try
        {
            int count = 0;
            foreach (ulong connectionId in statelessResetTokensByConnectionId.Keys)
            {
                rented[count++] = connectionId;
            }

            int checksum = 0;
            for (int index = 0; index < count; index++)
            {
                checksum += unchecked((int)rented[index]);
            }

            return checksum;
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(rented, clearArray: true);
        }
    }
}
