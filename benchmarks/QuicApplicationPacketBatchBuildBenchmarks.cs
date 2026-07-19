// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares per-packet protected-buffer leases with direct construction into one contiguous batch owner.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationPacketBatchBuildBenchmarks
{
    private const int MaximumProtectedPacketLength = 2048;
    private static readonly byte[] DestinationConnectionId = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];

    private readonly byte[] applicationPayload = new byte[1400];
    private QuicHandshakeFlowCoordinator individualPacketCoordinator = null!;
    private QuicHandshakeFlowCoordinator contiguousBatchCoordinator = null!;
    private QuicTlsPacketProtectionMaterial packetProtectionMaterial;

    /// <summary>
    /// Gets or sets the number of packets constructed per benchmark operation.
    /// </summary>
    [Params(1, 4, 12)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Prepares deterministic packet payload and protection state.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        applicationPayload.AsSpan().Fill(0x5A);
        packetProtectionMaterial = CreatePacketProtectionMaterial();
        individualPacketCoordinator = new QuicHandshakeFlowCoordinator(DestinationConnectionId);
        contiguousBatchCoordinator = new QuicHandshakeFlowCoordinator(DestinationConnectionId);
    }

    /// <summary>
    /// Builds each protected packet into its own pooled lease.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int IndividualPooledPacketLeases()
    {
        int checksum = 0;
        for (int index = 0; index < PacketCount; index++)
        {
            QuicBufferLease protectedPacket = default;
            try
            {
                if (!individualPacketCoordinator.TryBuildProtectedApplicationDataPacketLease(
                        applicationPayload,
                        packetProtectionMaterial,
                        keyPhase: false,
                        out _,
                        out protectedPacket))
                {
                    return -1;
                }

                checksum = unchecked(checksum + protectedPacket.Length + protectedPacket.Span[0]);
            }
            finally
            {
                protectedPacket.Dispose();
            }
        }

        return checksum;
    }

    /// <summary>
    /// Builds the same packets directly into fixed slices of one pooled batch owner.
    /// </summary>
    [Benchmark]
    public int ContiguousPooledPacketBatch()
    {
        byte[] batchOwner = QuicBufferPool.RentBytes(
            checked(PacketCount * MaximumProtectedPacketLength),
            QuicBufferPoolOwner.OutboundPacketProtection);
        try
        {
            int checksum = 0;
            for (int index = 0; index < PacketCount; index++)
            {
                Span<byte> packetDestination = batchOwner.AsSpan(
                    index * MaximumProtectedPacketLength,
                    MaximumProtectedPacketLength);
                if (!contiguousBatchCoordinator.TryBuildProtectedApplicationDataPacket(
                        applicationPayload,
                        packetProtectionMaterial,
                        keyPhase: false,
                        spinBit: true,
                        greaseQuicBit: false,
                        packetDestination,
                        out _,
                        out int protectedPacketLength))
                {
                    return -1;
                }

                checksum = unchecked(checksum + protectedPacketLength + packetDestination[0]);
            }

            return checksum;
        }
        finally
        {
            QuicBufferPool.ReturnBytes(batchOwner);
        }
    }

    private static QuicTlsPacketProtectionMaterial CreatePacketProtectionMaterial()
    {
        if (!QuicTlsPacketProtectionMaterial.TryCreate(
                QuicTlsEncryptionLevel.OneRtt,
                QuicAeadAlgorithm.Aes128Gcm,
                Enumerable.Range(0x10, 16).Select(static value => (byte)value).ToArray(),
                Enumerable.Range(0x20, 12).Select(static value => (byte)value).ToArray(),
                Enumerable.Range(0x30, 16).Select(static value => (byte)value).ToArray(),
                new QuicAeadUsageLimits(1UL << 40, 1UL << 40),
                out QuicTlsPacketProtectionMaterial material))
        {
            throw new InvalidOperationException("Failed to create benchmark packet-protection material.");
        }

        return material;
    }
}
