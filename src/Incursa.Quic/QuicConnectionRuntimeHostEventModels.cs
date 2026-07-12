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
    private const byte HasRoutedConnectionIdFlag = 1 << 0;
    private const byte HasEcnCountsFlag = 1 << 1;

    private readonly object? connectionEventOrOwnedDatagramBuffer;
    private readonly QuicConnectionPathIdentity packetPathIdentity;
    private readonly QuicEcnCounts packetEcnCounts;
    private readonly ReadOnlyMemory<byte> packetDatagramOrStreamData;
    private readonly long observedAtTicksOrRequestId;
    private readonly ulong routedConnectionIdOrStreamId;
    private readonly int streamTypeOrActionKind;
    private readonly byte flags;

    internal QuicConnectionRuntimeShardWorkItem(
        QuicConnectionHandle handle,
        QuicConnectionRuntime runtime,
        QuicConnectionEvent connectionEvent)
    {
        Handle = handle;
        Runtime = runtime;
        connectionEventOrOwnedDatagramBuffer = connectionEvent;
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
        connectionEventOrOwnedDatagramBuffer = ownedDatagramBuffer;
        Kind = QuicConnectionRuntimeShardWorkItemKind.PacketReceived;
        packetPathIdentity = packetReceived.PathIdentity;
        packetEcnCounts = packetReceived.EcnCounts.GetValueOrDefault();
        packetDatagramOrStreamData = packetReceived.Datagram;
        observedAtTicksOrRequestId = packetReceived.ObservedAtTicks;
        routedConnectionIdOrStreamId = packetReceived.RoutedLocallyIssuedConnectionId.GetValueOrDefault();
        flags = (byte)(
            (packetReceived.RoutedLocallyIssuedConnectionId.HasValue ? HasRoutedConnectionIdFlag : 0)
            | (packetReceived.EcnCounts.HasValue ? HasEcnCountsFlag : 0));
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
        Kind = QuicConnectionRuntimeShardWorkItemKind.StreamOpen;
        observedAtTicksOrRequestId = requestId;
        streamTypeOrActionKind = (int)streamType;
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
        Kind = QuicConnectionRuntimeShardWorkItemKind.StreamWrite;
        observedAtTicksOrRequestId = requestId;
        streamTypeOrActionKind = (int)actionKind;
        routedConnectionIdOrStreamId = streamId;
        packetDatagramOrStreamData = streamData;
    }

    internal QuicConnectionRuntimeShardWorkItemKind Kind { get; }

    internal QuicConnectionHandle Handle { get; }

    internal QuicConnectionRuntime? Runtime { get; }

    internal QuicConnectionEvent? ConnectionEvent => Kind == QuicConnectionRuntimeShardWorkItemKind.Event
        ? connectionEventOrOwnedDatagramBuffer as QuicConnectionEvent
        : null;

    internal QuicConnectionPacketReceivedContext PacketReceived => GetPacketReceived();

    internal byte[]? OwnedDatagramBuffer => Kind == QuicConnectionRuntimeShardWorkItemKind.PacketReceived
        ? connectionEventOrOwnedDatagramBuffer as byte[]
        : null;

    internal QuicReceiveBufferOwnership OwnedDatagramBufferOwnership { get; }

    internal long RequestId => Kind is QuicConnectionRuntimeShardWorkItemKind.StreamOpen
        or QuicConnectionRuntimeShardWorkItemKind.StreamWrite
        ? observedAtTicksOrRequestId
        : 0;

    internal QuicStreamType StreamType => Kind == QuicConnectionRuntimeShardWorkItemKind.StreamOpen
        ? (QuicStreamType)streamTypeOrActionKind
        : default;

    internal QuicConnectionStreamActionKind StreamActionKind => Kind == QuicConnectionRuntimeShardWorkItemKind.StreamWrite
        ? (QuicConnectionStreamActionKind)streamTypeOrActionKind
        : default;

    internal ulong StreamId => Kind == QuicConnectionRuntimeShardWorkItemKind.StreamWrite
        ? routedConnectionIdOrStreamId
        : 0;

    internal ReadOnlyMemory<byte> StreamData => Kind == QuicConnectionRuntimeShardWorkItemKind.StreamWrite
        ? packetDatagramOrStreamData
        : default;

    internal long EnqueuedTimestamp { get; init; }

    private bool HasFlag(byte flag) => (flags & flag) != 0;

    private QuicConnectionPacketReceivedContext GetPacketReceived()
    {
        if (Kind != QuicConnectionRuntimeShardWorkItemKind.PacketReceived)
        {
            return default;
        }

        ulong? routedConnectionId = HasFlag(HasRoutedConnectionIdFlag)
            ? routedConnectionIdOrStreamId
            : null;
        QuicEcnCounts? ecnCounts = HasFlag(HasEcnCountsFlag)
            ? packetEcnCounts
            : null;
        return new QuicConnectionPacketReceivedContext(
            observedAtTicksOrRequestId,
            packetPathIdentity,
            packetDatagramOrStreamData,
            routedConnectionId,
            ecnCounts);
    }
}
