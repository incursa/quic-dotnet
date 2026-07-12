// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares fixed sent-packet dictionary populations using the former and packed value layouts.
/// </summary>
[MemoryDiagnoser]
public class QuicConnectionSentPacketValueBenchmarks
{
    /// <summary>
    /// Gets or sets the number of sent-packet entries populated per operation.
    /// </summary>
    [Params(128, 1_024, 8_192)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Populates a dictionary using the former 136-byte positional record shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int PopulateDictionaryWithFormerValue()
    {
        Dictionary<QuicConnectionSentPacketKey, FormerSentPacket> packets = new();
        for (int index = 0; index < PacketCount; index++)
        {
            packets.Add(
                new QuicConnectionSentPacketKey(QuicPacketNumberSpace.ApplicationData, (ulong)index),
                new FormerSentPacket(
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

    /// <summary>
    /// Populates a dictionary using the packed production value.
    /// </summary>
    [Benchmark]
    public int PopulateDictionaryWithPackedValue()
    {
        Dictionary<QuicConnectionSentPacketKey, QuicConnectionSentPacket> packets = new();
        for (int index = 0; index < PacketCount; index++)
        {
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

    private readonly record struct FormerSentPacket(
        QuicPacketNumberSpace PacketNumberSpace,
        ulong PacketNumber,
        ulong PayloadBytes,
        ulong SentAtMicros,
        bool AckEliciting = true,
        bool AckOnlyPacket = false,
        bool ProbePacket = false,
        bool Retransmittable = true,
        QuicConnectionCryptoSendMetadata? CryptoMetadata = null,
        ReadOnlyMemory<byte> PacketBytes = default,
        QuicTlsEncryptionLevel? PacketProtectionLevel = null,
        ulong? StreamId = null,
        ulong[]? StreamIds = null,
        ReadOnlyMemory<byte> PlaintextPayload = default,
        ulong? OneRttKeyPhase = null,
        byte[]? PlaintextPayloadOwner = null,
        byte[]? PacketBytesOwner = null);
}
