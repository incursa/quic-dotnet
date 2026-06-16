// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes how a CONNECT-UDP endpoint handles an HTTP Datagram received before its request.
/// </summary>
public enum Http3ConnectUdpEarlyDatagramAction
{
    /// <summary>
    /// Process the datagram because the corresponding request is known.
    /// </summary>
    Process,

    /// <summary>
    /// Silently drop the datagram.
    /// </summary>
    DropSilently,

    /// <summary>
    /// Temporarily buffer the datagram while awaiting the request.
    /// </summary>
    BufferTemporarily,
}
