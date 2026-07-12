// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the sent-packet dictionary footprint of the former two-field key with the packed key.
/// </summary>
[MemoryDiagnoser]
public class QuicConnectionSentPacketKeyBenchmarks
{
    /// <summary>
    /// Gets or sets the number of sent-packet entries populated per operation.
    /// </summary>
    [Params(128, 1_024, 8_192)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Populates a dictionary using the former naturally aligned 16-byte key shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PopulateDictionaryWithTwoFieldKey()
    {
        Dictionary<TwoFieldSentPacketKey, int> packets = new();
        for (int index = 0; index < PacketCount; index++)
        {
            packets.Add(
                new TwoFieldSentPacketKey(QuicPacketNumberSpace.ApplicationData, (ulong)index),
                index);
        }

        return packets.Count;
    }

    /// <summary>
    /// Populates a dictionary using the packed production key.
    /// </summary>
    [Benchmark]
    public int PopulateDictionaryWithPackedKey()
    {
        Dictionary<QuicConnectionSentPacketKey, int> packets = new();
        for (int index = 0; index < PacketCount; index++)
        {
            packets.Add(
                new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, (ulong)index),
                index);
        }

        return packets.Count;
    }

    private readonly record struct TwoFieldSentPacketKey(
        QuicPacketNumberSpace PacketNumberSpace,
        ulong PacketNumber);
}
