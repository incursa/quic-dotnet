// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Benchmarks packet-number sorted map insertion shapes used by ACK and recovery state.
/// </summary>
[MemoryDiagnoser]
public class QuicPacketNumberSortedMapBenchmarks
{
    private ulong[] packetNumbers = [];

    /// <summary>
    /// Number of packet records inserted into the sorted map.
    /// </summary>
    [Params(1024, 10000)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Packet-number arrival pattern.
    /// </summary>
    [Params(PacketNumberInsertPattern.Monotonic, PacketNumberInsertPattern.NearMonotonic)]
    public PacketNumberInsertPattern Pattern { get; set; }

    /// <summary>
    /// Builds the packet-number sequence used by each benchmark invocation.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        packetNumbers = new ulong[PacketCount];
        for (int index = 0; index < packetNumbers.Length; index++)
        {
            packetNumbers[index] = (ulong)index;
        }

        if (Pattern == PacketNumberInsertPattern.NearMonotonic)
        {
            for (int index = 0; index + 1 < packetNumbers.Length; index += 8)
            {
                (packetNumbers[index], packetNumbers[index + 1]) = (packetNumbers[index + 1], packetNumbers[index]);
            }
        }
    }

    /// <summary>
    /// Measures the previous red-black tree backed map shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int SortedDictionaryInsert()
    {
        SortedDictionary<ulong, ulong> map = [];
        foreach (ulong packetNumber in packetNumbers)
        {
            map[packetNumber] = packetNumber;
        }

        return map.Count;
    }

    /// <summary>
    /// Measures the array-backed sorted map shape now used by packet-number tracking.
    /// </summary>
    [Benchmark]
    public int SortedListInsert()
    {
        SortedList<ulong, ulong> map = [];
        foreach (ulong packetNumber in packetNumbers)
        {
            map[packetNumber] = packetNumber;
        }

        return map.Count;
    }

    /// <summary>
    /// Packet number insertion pattern.
    /// </summary>
    public enum PacketNumberInsertPattern
    {
        /// <summary>
        /// Packet numbers are inserted in strictly increasing order.
        /// </summary>
        Monotonic,

        /// <summary>
        /// Packet numbers are mostly increasing with small adjacent reordering.
        /// </summary>
        NearMonotonic,
    }
}
