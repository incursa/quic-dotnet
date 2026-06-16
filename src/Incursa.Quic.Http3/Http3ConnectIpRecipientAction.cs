// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Describes how a CONNECT-IP request recipient handles an accepted request.
/// </summary>
public enum Http3ConnectIpRecipientAction
{
    /// <summary>
    /// Forward the request to a configured upstream HTTP server.
    /// </summary>
    ForwardToConfiguredHttpServer,

    /// <summary>
    /// Act as the IP proxy for the request.
    /// </summary>
    ActAsIpProxy,
}
