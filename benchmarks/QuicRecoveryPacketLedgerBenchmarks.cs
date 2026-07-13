// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the former combined recovery value with the common and transition cases of the split ledger.
/// </summary>
[MemoryDiagnoser]
public class QuicRecoveryPacketLedgerBenchmarks
{
    /// <summary>
    /// Gets or sets the number of recovery entries populated per operation.
    /// </summary>
    [Params(128, 1_024, 8_192)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Populates a sorted ledger using the former 24-byte packed value shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PopulateCombinedStateLedger()
    {
        SortedList<ulong, FormerRecoverySentPacketState> packets = new(32);
        for (int index = 0; index < PacketCount; index++)
        {
            packets.Add((ulong)index, new FormerRecoverySentPacketState(
                (ulong)index,
                QuicTlsEncryptionLevel.OneRtt,
                0));
        }

        return packets.Count;
    }

    /// <summary>
    /// Populates the split steady-state ledger where all packets share metadata.
    /// </summary>
    [Benchmark]
    public int PopulateSplitCommonMetadataLedger()
    {
        SortedList<ulong, ulong> sentTimesMicros = new(32);
        QuicRecoverySentPacketMetadata metadata = new(QuicTlsEncryptionLevel.OneRtt, 0);
        for (int index = 0; index < PacketCount; index++)
        {
            sentTimesMicros.Add((ulong)index, (ulong)index);
        }

        return sentTimesMicros.Count + (metadata.OneRttKeyPhase.HasValue ? 0 : 1);
    }

    /// <summary>
    /// Populates a split ledger with one packet from a new key-update epoch.
    /// </summary>
    [Benchmark]
    public int PopulateSplitSingleMetadataTransitionLedger()
    {
        SortedList<ulong, ulong> sentTimesMicros = new(32);
        Dictionary<ulong, QuicRecoverySentPacketMetadata>? nonDefaultMetadata = null;
        for (int index = 0; index < PacketCount; index++)
        {
            ulong packetNumber = (ulong)index;
            sentTimesMicros.Add(packetNumber, packetNumber);
            if (index == PacketCount - 1)
            {
                (nonDefaultMetadata ??= new Dictionary<ulong, QuicRecoverySentPacketMetadata>())[packetNumber] =
                    new QuicRecoverySentPacketMetadata(QuicTlsEncryptionLevel.OneRtt, 1);
            }
        }

        return sentTimesMicros.Count + (nonDefaultMetadata?.Count ?? 0);
    }

    /// <summary>
    /// Populates the transition worst case where half the in-flight packets use a new epoch.
    /// </summary>
    [Benchmark]
    public int PopulateSplitHalfMetadataTransitionLedger()
    {
        SortedList<ulong, ulong> sentTimesMicros = new(32);
        Dictionary<ulong, QuicRecoverySentPacketMetadata> nonDefaultMetadata = new();
        int transitionAt = PacketCount / 2;
        for (int index = 0; index < PacketCount; index++)
        {
            ulong packetNumber = (ulong)index;
            sentTimesMicros.Add(packetNumber, packetNumber);
            if (index >= transitionAt)
            {
                nonDefaultMetadata[packetNumber] =
                    new QuicRecoverySentPacketMetadata(QuicTlsEncryptionLevel.OneRtt, 1);
            }
        }

        return sentTimesMicros.Count + nonDefaultMetadata.Count;
    }

    private readonly record struct FormerRecoverySentPacketState(
        ulong SentAtMicros,
        QuicTlsEncryptionLevel? PacketProtectionLevel,
        ulong? OneRttKeyPhase);
}
