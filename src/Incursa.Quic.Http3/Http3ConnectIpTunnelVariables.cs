// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic.Http3;

/// <summary>
/// Contains decoded and validated CONNECT-IP tunnel variables.
/// </summary>
public sealed class Http3ConnectIpTunnelVariables
{
    /// <summary>
    /// Initializes a new instance of the <see cref="Http3ConnectIpTunnelVariables" /> class.
    /// </summary>
    public Http3ConnectIpTunnelVariables(Http3ConnectIpTargetScope target, Http3ConnectIpProtocolScope ipproto)
    {
        Target = target ?? throw new ArgumentNullException(nameof(target));
        Ipproto = ipproto ?? throw new ArgumentNullException(nameof(ipproto));
    }

    /// <summary>
    /// Gets the validated target scope.
    /// </summary>
    public Http3ConnectIpTargetScope Target { get; }

    /// <summary>
    /// Gets the validated ipproto scope.
    /// </summary>
    public Http3ConnectIpProtocolScope Ipproto { get; }
}
