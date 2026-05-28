// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

/// <summary>
/// Classifies the terminal QUIC error state surfaced to consumers.
/// </summary>
public enum QuicError
{
    Success = 0,
    InternalError = 1,
    ConnectionAborted = 2,
    StreamAborted = 3,
    ConnectionTimeout = 6,
    ConnectionRefused = 8,
    VersionNegotiationError = 9,
    ConnectionIdle = 10,
    OperationAborted = 12,
    AlpnInUse = 13,
    TransportError = 14,
    CallbackError = 15,
}

