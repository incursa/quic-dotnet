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

internal readonly record struct QuicConnectionRuntimeShardWorkItem(
    QuicConnectionHandle Handle,
    QuicConnectionRuntime Runtime,
    QuicConnectionEvent ConnectionEvent);
