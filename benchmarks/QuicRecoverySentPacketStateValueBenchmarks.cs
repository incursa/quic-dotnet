// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares fixed recovery-ledger populations using the former and packed value layouts.
/// </summary>
[MemoryDiagnoser]
public class QuicRecoverySentPacketStateValueBenchmarks
{
    /// <summary>
    /// Gets or sets the number of recovery entries populated per operation.
    /// </summary>
    [Params(128, 1_024, 8_192)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Populates a sorted recovery ledger using the former 32-byte nullable value shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PopulateSortedListWithFormerValue()
    {
        SortedList<ulong, FormerRecoverySentPacketState> packets = new(64);
        for (int index = 0; index < PacketCount; index++)
        {
            packets.Add((ulong)index, new FormerRecoverySentPacketState((ulong)index, QuicTlsEncryptionLevel.OneRtt, 0));
        }

        return packets.Count;
    }

    /// <summary>
    /// Populates a sorted recovery ledger using the packed production value.
    /// </summary>
    [Benchmark]
    public int PopulateSortedListWithPackedValue()
    {
        SortedList<ulong, QuicRecoverySentPacketState> packets = new(64);
        for (int index = 0; index < PacketCount; index++)
        {
            packets.Add((ulong)index, new QuicRecoverySentPacketState((ulong)index, QuicTlsEncryptionLevel.OneRtt, 0));
        }

        return packets.Count;
    }

    private readonly record struct FormerRecoverySentPacketState(
        ulong SentAtMicros,
        QuicTlsEncryptionLevel? PacketProtectionLevel,
        ulong? OneRttKeyPhase);
}
