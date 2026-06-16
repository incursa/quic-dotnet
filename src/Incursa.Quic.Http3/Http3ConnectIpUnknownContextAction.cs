// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes RFC 9484 handling for an HTTP Datagram with an unknown CONNECT-IP Context ID.
/// </summary>
public enum Http3ConnectIpUnknownContextAction
{
    /// <summary>
    /// Silently drop the datagram.
    /// </summary>
    DropSilently,

    /// <summary>
    /// Temporarily buffer the datagram while awaiting Context ID registration.
    /// </summary>
    BufferTemporarily,
}
