// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Sockets;
using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares the Linux batch send feasibility primitive with repeated <see cref="Socket.SendTo(ReadOnlySpan{byte}, SocketFlags, SocketAddress)" />
/// calls for the same datagram batch sizes.
/// </summary>
[MemoryDiagnoser]
public class QuicSocketSendBatchBenchmarks
{
    private const int PayloadLength = 1200;

    private readonly byte[] receiveBuffer = new byte[2048];
    private Socket sender = null!;
    private Socket receiver = null!;
    private SocketAddress receiverAddress = null!;
    private QuicSocketSendBatchMessage[] batchMessages = [];
    private byte[][] repeatedSendBuffers = [];

    /// <summary>
    /// Gets or sets the number of datagrams sent per benchmark invocation.
    /// </summary>
    [Params(1, 4, 8, 16, 32)]
    public int BatchSize { get; set; }

    /// <summary>
    /// Prepares the sender, receiver, and batch payloads used by both paths.
    /// </summary>
    [GlobalSetup]
    public void GlobalSetup()
    {
        sender = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        receiver.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        receiver.ReceiveTimeout = (int)TimeSpan.FromSeconds(5).TotalMilliseconds;
        receiverAddress = ((IPEndPoint)receiver.LocalEndPoint!).Serialize();

        repeatedSendBuffers = new byte[BatchSize][];
        batchMessages = new QuicSocketSendBatchMessage[BatchSize];

        for (int index = 0; index < BatchSize; index++)
        {
            byte[] payload = new byte[PayloadLength];
            payload.AsSpan().Fill((byte)(index + 1));

            repeatedSendBuffers[index] = payload;
            batchMessages[index] = new QuicSocketSendBatchMessage(payload, receiverAddress);
        }
    }

    /// <summary>
    /// Releases the benchmark sockets after each run.
    /// </summary>
    [GlobalCleanup]
    public void GlobalCleanup()
    {
        sender.Dispose();
        receiver.Dispose();
    }

    /// <summary>
    /// Measures the new batch primitive.
    /// </summary>
    [Benchmark(Baseline = true)]
    public int RepeatedSendTo()
    {
        int sentBytes = 0;

        foreach (byte[] payload in repeatedSendBuffers)
        {
            sentBytes += sender.SendTo(payload, SocketFlags.None, receiverAddress);
        }

        DrainReceiver();
        return sentBytes;
    }

    /// <summary>
    /// Measures the new batch primitive.
    /// </summary>
    [Benchmark]
    public int SendBatch()
    {
        QuicSocketSendBatchResult result = QuicSocketSendBatch.Send(sender, batchMessages);
        DrainReceiver();
        return result.SentBytes;
    }

    private void DrainReceiver()
    {
        for (int index = 0; index < BatchSize; index++)
        {
            _ = receiver.Receive(receiveBuffer, SocketFlags.None);
        }
    }
}
