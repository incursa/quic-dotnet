// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the former sent-packet scan with the per-stream outstanding-packet index.
/// </summary>
[MemoryDiagnoser]
public class QuicOutstandingSentStreamPacketLookupBenchmarks
{
    private QuicConnectionSentPacket[] packets = null!;
    private QuicOutstandingSentStreamPacketIndex index;
    private ulong targetStreamId;

    /// <summary>
    /// Gets or sets the number of retained packets searched for one acknowledged stream.
    /// </summary>
    [Params(64, 256, 1_024)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Creates the retained packet ledger and its candidate side index.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        packets = new QuicConnectionSentPacket[PacketCount];
        index = new QuicOutstandingSentStreamPacketIndex();
        targetStreamId = (ulong)(PacketCount - 1);
        for (int packetIndex = 0; packetIndex < packets.Length; packetIndex++)
        {
            byte[] payload = QuicBenchmarkData.BuildStreamFrame(
                frameType: 0x0A,
                streamId: (ulong)packetIndex,
                includeOffset: false,
                offset: 0,
                includeLength: true,
                streamData: [0x5A]);
            packets[packetIndex] = new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                PacketNumber: (ulong)packetIndex,
                PayloadBytes: (ulong)payload.Length,
                SentAtMicros: (ulong)packetIndex,
                PlaintextPayload: payload);
            index.Add(packets[packetIndex]);
        }
    }

    /// <summary>
    /// Scans every retained packet and parses its payload, matching the former ACK-time lookup.
    /// </summary>
    [Benchmark(Baseline = true)]
    public bool ScanRetainedPackets()
    {
        foreach (QuicConnectionSentPacket packet in packets)
        {
            if (QuicFramePayloadInspector.ContainsStreamDataForStream(
                packet.PlaintextPayload.Span,
                targetStreamId))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Looks up the same stream in the candidate side index.
    /// </summary>
    [Benchmark]
    public bool IndexedLookup() => index.GetCount(targetStreamId) > 0;
}

/// <summary>
/// Measures the insertion and removal overhead paid to maintain the side index.
/// </summary>
[MemoryDiagnoser]
public class QuicOutstandingSentStreamPacketBookkeepingBenchmarks
{
    private QuicConnectionSentPacket[] packets = null!;

    /// <summary>
    /// Gets or sets the number of sent packets processed per operation.
    /// </summary>
    [Params(64, 256, 1_024)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Creates representative one-stream packets outside the measured operation.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        packets = new QuicConnectionSentPacket[PacketCount];
        for (int packetIndex = 0; packetIndex < packets.Length; packetIndex++)
        {
            byte[] payload = QuicBenchmarkData.BuildStreamFrame(
                frameType: 0x0A,
                streamId: (ulong)(packetIndex % 64),
                includeOffset: false,
                offset: 0,
                includeLength: true,
                streamData: [0x5A]);
            packets[packetIndex] = new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                PacketNumber: (ulong)packetIndex,
                PayloadBytes: (ulong)payload.Length,
                SentAtMicros: (ulong)packetIndex,
                PlaintextPayload: payload);
        }
    }

    /// <summary>
    /// Parses each packet twice, isolating the candidate dictionary cost from its required parser work.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ParsePacketsTwice()
    {
        int streamCount = 0;
        Span<ulong> inlineStreamIds = stackalloc ulong[4];
        foreach (QuicConnectionSentPacket packet in packets)
        {
            for (int pass = 0; pass < 2; pass++)
            {
                streamCount += QuicFramePayloadInspector.CopyStreamDataStreamIds(
                    packet.PlaintextPayload.Span,
                    inlineStreamIds,
                    out _);
            }
        }

        return streamCount;
    }

    /// <summary>
    /// Adds and removes every packet from the candidate index.
    /// </summary>
    [Benchmark]
    public int AddAndRemovePackets()
    {
        QuicOutstandingSentStreamPacketIndex candidate = new();
        foreach (QuicConnectionSentPacket packet in packets)
        {
            candidate.Add(packet);
        }

        foreach (QuicConnectionSentPacket packet in packets)
        {
            candidate.Remove(packet);
        }

        return candidate.GetCount(0);
    }
}

/// <summary>
/// Compares the complete former and indexed stream-data acknowledgment lifecycles.
/// </summary>
[MemoryDiagnoser]
public class QuicOutstandingSentStreamPacketLifecycleBenchmarks
{
    private QuicConnectionSentPacket[] packets = null!;

    /// <summary>
    /// Gets or sets the number of retained packets acknowledged per operation.
    /// </summary>
    [Params(64, 256, 1_024)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Creates one packet per stream so each acknowledgment reaches the RESET_STREAM suppression check.
    /// </summary>
    [GlobalSetup]
    public void Setup()
    {
        packets = new QuicConnectionSentPacket[PacketCount];
        for (int packetIndex = 0; packetIndex < packets.Length; packetIndex++)
        {
            byte[] payload = QuicBenchmarkData.BuildStreamFrame(
                frameType: 0x0A,
                streamId: (ulong)packetIndex,
                includeOffset: false,
                offset: 0,
                includeLength: true,
                streamData: [0x5A]);
            packets[packetIndex] = new QuicConnectionSentPacket(
                QuicPacketNumberSpace.ApplicationData,
                PacketNumber: (ulong)packetIndex,
                PayloadBytes: (ulong)payload.Length,
                SentAtMicros: (ulong)packetIndex,
                PlaintextPayload: payload);
        }
    }

    /// <summary>
    /// Scans the remaining retained packets after each acknowledgment, matching the former behavior.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int ScanAfterEveryAcknowledgment()
    {
        int streamsWithoutOutstandingData = 0;
        for (int acknowledgedIndex = 0; acknowledgedIndex < packets.Length; acknowledgedIndex++)
        {
            ulong acknowledgedStreamId = (ulong)acknowledgedIndex;
            bool found = false;
            for (int retainedIndex = acknowledgedIndex + 1; retainedIndex < packets.Length; retainedIndex++)
            {
                if (QuicFramePayloadInspector.ContainsStreamDataForStream(
                    packets[retainedIndex].PlaintextPayload.Span,
                    acknowledgedStreamId))
                {
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                streamsWithoutOutstandingData++;
            }
        }

        return streamsWithoutOutstandingData;
    }

    /// <summary>
    /// Builds the side index, removes each acknowledged packet, and checks its stream count.
    /// </summary>
    [Benchmark]
    public int IndexEveryPacketLifecycle()
    {
        QuicOutstandingSentStreamPacketIndex candidate = new();
        foreach (QuicConnectionSentPacket packet in packets)
        {
            candidate.Add(packet);
        }

        int streamsWithoutOutstandingData = 0;
        for (int acknowledgedIndex = 0; acknowledgedIndex < packets.Length; acknowledgedIndex++)
        {
            QuicConnectionSentPacket packet = packets[acknowledgedIndex];
            candidate.Remove(packet);
            if (candidate.GetCount((ulong)acknowledgedIndex) == 0)
            {
                streamsWithoutOutstandingData++;
            }
        }

        return streamsWithoutOutstandingData;
    }
}
