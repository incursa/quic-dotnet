// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

internal readonly record struct QuicConnectionRuntimeRoute(
    int ShardIndex,
    QuicConnectionRuntime Runtime);

internal readonly record struct QuicConnectionRuntimeShardWorkItem(
    QuicConnectionHandle Handle,
    QuicConnectionRuntime Runtime,
    QuicConnectionEvent ConnectionEvent);
