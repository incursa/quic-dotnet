// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Identifies the QUIC endpoint that initiated a stream.
/// </summary>
public enum Http3StreamInitiator
{
    /// <summary>
    /// The stream was initiated by the client.
    /// </summary>
    Client,

    /// <summary>
    /// The stream was initiated by the server.
    /// </summary>
    Server,
}
