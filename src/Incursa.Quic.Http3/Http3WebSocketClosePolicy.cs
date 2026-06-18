// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes a WebSocket close status and optional reason selected by HTTP/3 server policy.
/// </summary>
public readonly record struct Http3WebSocketClosePolicy(ushort StatusCode, string? Reason);
