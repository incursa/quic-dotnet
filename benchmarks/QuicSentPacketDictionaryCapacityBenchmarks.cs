// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares fixed and demand-triggered capacity strategies for the sent-packet ledger.
/// </summary>
[MemoryDiagnoser]
public class QuicSentPacketDictionaryCapacityBenchmarks
{
    private const int InitialCapacity = 64;
    private const int IntermediateReserveThreshold = 512;
    private const int HighReserveThreshold = 1_536;
    private const int IntermediateSustainedCapacity = 1_024;
    private const int HighSustainedCapacity = 2_048;

    /// <summary>
    /// Gets or sets the number of retained sent packets populated per operation.
    /// </summary>
    [Params(128, 512, 1_024, 1_536, 1_664, 2_048)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Populates the ledger using only the current fixed initial capacity.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PopulateWithFixedInitialCapacity()
        => Populate(reserveThreshold: 0, sustainedCapacity: 0);

    /// <summary>
    /// Reserves additional space only after the ledger reaches sustained pressure.
    /// </summary>
    [Benchmark]
    public int PopulateWithIntermediateDemandTriggeredCapacity()
        => Populate(IntermediateReserveThreshold, IntermediateSustainedCapacity);

    /// <summary>
    /// Reserves enough space for the measured high-pressure ledger in one step.
    /// </summary>
    [Benchmark]
    public int PopulateWithLateHighDemandTriggeredCapacity()
        => Populate(HighReserveThreshold, HighSustainedCapacity);

    private int Populate(int reserveThreshold, int sustainedCapacity)
    {
        Dictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> packets = new(InitialCapacity);
        for (int index = 0; index < PacketCount; index++)
        {
            if (sustainedCapacity > 0 && packets.Count == reserveThreshold)
            {
                packets.EnsureCapacity(sustainedCapacity);
            }

            packets.Add(
                new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, (ulong)index),
                new QuicConnectionSentPacket(
                    QuicPacketNumberSpace.ApplicationData,
                    (ulong)index,
                    1_200,
                    (ulong)index,
                    PacketProtectionLevel: QuicTlsEncryptionLevel.OneRtt,
                    StreamId: (ulong)index,
                    OneRttKeyPhase: 0));
        }

        return packets.Count;
    }
}
