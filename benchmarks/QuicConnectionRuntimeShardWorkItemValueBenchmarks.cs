// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using BenchmarkDotNet.Attributes;

namespace Incursa.Quic.Benchmarks;

/// <summary>
/// Compares channel-segment array allocation using the former and shared variant work-item layouts.
/// </summary>
[MemoryDiagnoser]
public class QuicConnectionRuntimeShardWorkItemValueBenchmarks
{
    /// <summary>
    /// Gets or sets the number of work-item slots allocated per operation.
    /// </summary>
    [Params(32, 128, 1_024)]
    public int ItemCount { get; set; }

    /// <summary>
    /// Allocates an array using the former 208-byte work-item shape.
    /// </summary>
    [Benchmark(Baseline = true)]
    public object AllocateFormerWorkItemArray() => new FormerWorkItem[ItemCount];

    /// <summary>
    /// Allocates an array using the production shared variant work-item shape.
    /// </summary>
    [Benchmark]
    public object AllocateSharedVariantWorkItemArray() => new QuicConnectionRuntimeShardWorkItem[ItemCount];

    private readonly record struct FormerWorkItem(
        QuicConnectionHandle Handle,
        QuicConnectionRuntime? Runtime,
        QuicConnectionEvent? ConnectionEvent,
        QuicConnectionPacketReceivedContext PacketReceived,
        byte[]? OwnedDatagramBuffer,
        QuicReceiveBufferOwnership OwnedDatagramBufferOwnership,
        long RequestId,
        QuicStreamType StreamType,
        QuicConnectionStreamActionKind StreamActionKind,
        ulong StreamId,
        ReadOnlyMemory<byte> StreamData,
        long EnqueuedTimestamp);
}
