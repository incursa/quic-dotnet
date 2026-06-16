// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes the action selected for an RFC 9297 HTTP Datagram lifecycle decision.
/// </summary>
public enum Http3DatagramLifecycleAction
{
    /// <summary>
    /// The HTTP Datagram can be processed normally.
    /// </summary>
    Accept,

    /// <summary>
    /// The HTTP Datagram can be sent.
    /// </summary>
    Send,

    /// <summary>
    /// The HTTP Datagram should be silently dropped.
    /// </summary>
    DropSilently,

    /// <summary>
    /// The HTTP Datagram can be buffered temporarily while waiting for the associated stream.
    /// </summary>
    BufferTemporarily,

    /// <summary>
    /// The associated request stream should be aborted.
    /// </summary>
    AbortRequestStream,
}
