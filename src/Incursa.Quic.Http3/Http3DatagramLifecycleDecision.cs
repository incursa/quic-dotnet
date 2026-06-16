// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents an RFC 9297 HTTP Datagram lifecycle decision.
/// </summary>
public sealed class Http3DatagramLifecycleDecision
{
    internal Http3DatagramLifecycleDecision(Http3DatagramLifecycleAction action, Http3ErrorCode? errorCode = null)
    {
        Action = action;
        ErrorCode = errorCode;
    }

    /// <summary>
    /// Gets the selected lifecycle action.
    /// </summary>
    public Http3DatagramLifecycleAction Action { get; }

    /// <summary>
    /// Gets the HTTP/3 error code associated with an abort decision.
    /// </summary>
    public Http3ErrorCode? ErrorCode { get; }
}
