// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies the local HTTP/3 endpoint role.
/// </summary>
public enum Http3EndpointRole
{
    /// <summary>
    /// The local endpoint is the HTTP/3 client.
    /// </summary>
    Client,

    /// <summary>
    /// The local endpoint is the HTTP/3 server.
    /// </summary>
    Server,
}
