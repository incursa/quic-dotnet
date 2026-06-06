// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: Transport-parameter parsing and formatting need a stable endpoint-role discriminator,
// so the client/server values stay explicit rather than inferred from call context.
// SEE: QuicTransportParametersCodec
/// <summary>
/// Identifies the endpoint role for transport-parameter parsing and formatting.
/// </summary>
internal enum QuicTransportParameterRole
{
    /// <summary>
    /// The local endpoint is a client.
    /// </summary>
    Client = 0,

    /// <summary>
    /// The local endpoint is a server.
    /// </summary>
    Server = 1,
}
