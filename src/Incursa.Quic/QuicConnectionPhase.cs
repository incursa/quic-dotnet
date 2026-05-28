// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Identifies the explicit lifecycle phase of a connection runtime.
/// </summary>
internal enum QuicConnectionPhase
{
    Establishing = 0,
    Active = 1,
    Closing = 2,
    Draining = 3,
    Discarded = 4,
}
