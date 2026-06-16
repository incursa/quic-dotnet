// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Represents expanded HTTP request target components for CONNECT-IP.
/// </summary>
public sealed class Http3ConnectIpRequestTarget
{
    internal Http3ConnectIpRequestTarget(string scheme, string authority, string pathAndQuery)
    {
        Scheme = scheme;
        Authority = authority;
        PathAndQuery = pathAndQuery;
    }

    /// <summary>
    /// Gets the expanded :scheme value.
    /// </summary>
    public string Scheme { get; }

    /// <summary>
    /// Gets the IP proxy :authority value.
    /// </summary>
    public string Authority { get; }

    /// <summary>
    /// Gets the expanded :path value including query when present.
    /// </summary>
    public string PathAndQuery { get; }
}
