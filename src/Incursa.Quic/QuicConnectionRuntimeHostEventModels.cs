// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: shard work items stay small and immutable for cross-thread handoff
// SEE: code:src/Incursa.Quic/QuicConnectionRuntimeHostEventModels.cs#QuicConnectionRuntimeRoute
// SEE: code:src/Incursa.Quic/QuicConnectionRuntimeShard.cs#TryPost
// The host stores routing metadata separately from the runtime, while the
// shard inbox carries the handle, runtime, and event together so enqueue and
// dequeue stay allocation-free and the shard can process the payload without a
// second route lookup.
internal readonly record struct QuicConnectionRuntimeRoute(
    int ShardIndex,
    QuicConnectionRuntime Runtime);

internal enum QuicConnectionRuntimeShardWorkItemKind
{
    Event = 0,
    PacketReceived = 1,
    StreamCapacityRelease = 2,
    FlowControlCreditUpdate = 3,
    StreamOpen = 4,
    StreamWrite = 5,
}

internal readonly record struct QuicConnectionRuntimeShardWorkItem
{
    internal QuicConnectionRuntimeShardWorkItem(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionEvent connectionEvent)
    {
        Handle = handle;
        Runtime = runtime;
        ConnectionEvent = connectionEvent;
        Kind = QuicConnectionRuntimeShardWorkItemKind.Event;
    }

    internal QuicConnectionRuntimeShardWorkItem(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionPacketReceivedContext packetReceived,
        byte[]? ownedDatagramBuffer,
        QuicReceiveBufferOwnership ownedDatagramBufferOwnership)
    {
        Handle = handle;
        Runtime = runtime;
        ConnectionEvent = null;
        Kind = QuicConnectionRuntimeShardWorkItemKind.PacketReceived;
        PacketReceived = packetReceived;
        OwnedDatagramBuffer = ownedDatagramBuffer;
        OwnedDatagramBufferOwnership = ownedDatagramBufferOwnership;
    }

    internal QuicConnectionRuntimeShardWorkItem(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionRuntimeShardWorkItemKind kind)
    {
        if (kind is not QuicConnectionRuntimeShardWorkItemKind.StreamCapacityRelease
            and not QuicConnectionRuntimeShardWorkItemKind.FlowControlCreditUpdate)
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Handle = handle;
        Runtime = runtime;
        ConnectionEvent = null;
        Kind = kind;
    }

    internal QuicConnectionRuntimeShardWorkItem(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        long requestId,
        QuicStreamType streamType)
    {
        Handle = handle;
        Runtime = runtime;
        ConnectionEvent = null;
        Kind = QuicConnectionRuntimeShardWorkItemKind.StreamOpen;
        RequestId = requestId;
        StreamType = streamType;
    }

    internal QuicConnectionRuntimeShardWorkItem(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        long requestId,
        QuicConnectionStreamActionKind actionKind,
        ulong streamId,
        ReadOnlyMemory<byte> streamData)
    {
        if (actionKind is not QuicConnectionStreamActionKind.Write and not QuicConnectionStreamActionKind.Finish)
        {
            throw new ArgumentOutOfRangeException(nameof(actionKind));
        }

        Handle = handle;
        Runtime = runtime;
        ConnectionEvent = null;
        Kind = QuicConnectionRuntimeShardWorkItemKind.StreamWrite;
        RequestId = requestId;
        StreamActionKind = actionKind;
        StreamId = streamId;
        StreamData = streamData;
    }

    internal QuicConnectionRuntimeShardWorkItemKind Kind { get; }

    internal QuicConnectionHandle Handle { get; }

    internal QuicConnectionRuntime? Runtime { get; }

    internal QuicConnectionEvent? ConnectionEvent { get; }

    internal QuicConnectionPacketReceivedContext PacketReceived { get; }

    internal byte[]? OwnedDatagramBuffer { get; }

    internal QuicReceiveBufferOwnership OwnedDatagramBufferOwnership { get; }

    internal long RequestId { get; }

    internal QuicStreamType StreamType { get; }

    internal QuicConnectionStreamActionKind StreamActionKind { get; }

    internal ulong StreamId { get; }

    internal ReadOnlyMemory<byte> StreamData { get; }
}
