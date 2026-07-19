// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares individual protected-packet construction and sends with one directly constructed UDP-segmented batch.
/// </summary>
[MemoryDiagnoser]
public class QuicApplicationPacketBatchSendBenchmarks
{
    private const int SegmentSize = 1472;
    private const int ApplicationPayloadLength = 1443;
    private const int DesiredReceiveBufferBytes = 4 * 1024 * 1024;

    private static readonly byte[] DestinationConnectionId = [0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08];

    private readonly byte[] applicationPayload = new byte[ApplicationPayloadLength];
    private readonly byte[] receiveBuffer = new byte[2048];
    private QuicHandshakeFlowCoordinator individualPacketCoordinator = null!;
    private QuicHandshakeFlowCoordinator contiguousBatchCoordinator = null!;
    private QuicTlsPacketProtectionMaterial packetProtectionMaterial;
    private Socket individualSender = null!;
    private Socket segmentedSender = null!;
    private Socket receiver = null!;
    private SocketAddress destination = null!;
    private CancellationTokenSource receiveCancellation = null!;
    private Task receiveTask = null!;

    /// <summary>
    /// Gets or sets the number of equal-size QUIC packets sent per operation.
    /// </summary>
    [Params(4, 12)]
    public int PacketCount { get; set; }

    /// <summary>
    /// Prepares deterministic packet protection state and loopback UDP sockets.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("This benchmark requires Windows UDP segmentation support.");
        }

        applicationPayload.AsSpan().Fill(0x5A);
        packetProtectionMaterial = CreatePacketProtectionMaterial();
        individualPacketCoordinator = new QuicHandshakeFlowCoordinator(DestinationConnectionId);
        contiguousBatchCoordinator = new QuicHandshakeFlowCoordinator(DestinationConnectionId);

        receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.ReceiveBufferSize = DesiredReceiveBufferBytes;
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        destination = ((IPEndPoint)receiver.LocalEndPoint!).Serialize();
        individualSender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        segmentedSender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        if (!QuicSocketUdpSegmentation.TryEnable(segmentedSender))
        {
            throw new PlatformNotSupportedException("Windows UDP segmentation could not be enabled.");
        }

        receiveCancellation = new CancellationTokenSource();
        receiveTask = Task.Run(ReceiveLoop);
    }

    /// <summary>
    /// Stops the receiver and releases sockets.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        receiveCancellation.Cancel();
        receiver.Dispose();
        try
        {
            receiveTask.GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
        }
        catch (ObjectDisposedException)
        {
        }

        individualSender.Dispose();
        segmentedSender.Dispose();
        receiveCancellation.Dispose();
    }

    /// <summary>
    /// Builds each protected packet into its own pooled lease and submits it separately.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int IndividualPacketSends()
    {
        int sentBytes = 0;
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
                        out protectedPacket)
                    || protectedPacket.Length != SegmentSize)
                {
                    return -1;
                }

                sentBytes += individualSender.SendTo(protectedPacket.Span, SocketFlags.None, destination);
            }
            finally
            {
                protectedPacket.Dispose();
            }
        }

        return sentBytes;
    }

    /// <summary>
    /// Builds the packets into one pooled owner and submits it through Windows UDP segmentation.
    /// </summary>
    [Benchmark]
    public int ContiguousSegmentedBatchSend()
    {
        int batchLength = checked(PacketCount * SegmentSize);
        byte[] batchOwner = QuicBufferPool.RentBytes(
            batchLength,
            QuicBufferPoolOwner.OutboundPacketProtection);
        try
        {
            for (int index = 0; index < PacketCount; index++)
            {
                Span<byte> packetDestination = batchOwner.AsSpan(index * SegmentSize, SegmentSize);
                if (!contiguousBatchCoordinator.TryBuildProtectedApplicationDataPacket(
                        applicationPayload,
                        packetProtectionMaterial,
                        keyPhase: false,
                        spinBit: true,
                        greaseQuicBit: false,
                        packetDestination,
                        out _,
                        out int protectedPacketLength)
                    || protectedPacketLength != SegmentSize)
                {
                    return -1;
                }
            }

            return QuicSocketUdpSegmentation.Send(
                segmentedSender,
                batchOwner.AsSpan(0, batchLength),
                PacketCount,
                destination);
        }
        finally
        {
            QuicBufferPool.ReturnBytes(batchOwner);
        }
    }

    private void ReceiveLoop()
    {
        while (!receiveCancellation.IsCancellationRequested)
        {
            try
            {
                _ = receiver.Receive(receiveBuffer, SocketFlags.None);
            }
            catch (SocketException) when (receiveCancellation.IsCancellationRequested)
            {
                return;
            }
            catch (ObjectDisposedException) when (receiveCancellation.IsCancellationRequested)
            {
                return;
            }
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
