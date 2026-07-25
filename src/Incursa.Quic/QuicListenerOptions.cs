// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;

namespace Incursa.Quic;

/// <summary>
/// Listener configuration for the public server entry surface.
/// </summary>
public sealed class QuicListenerOptions
{
    // CONTEXT: A zero backlog means "use the library default" rather than "accept nothing", so the
    // validation step normalizes the option before the listener host consumes it.
    // SEE: Validate
    private const int DefaultListenBacklog = 512;

    /// <summary>
    /// Initializes a new listener options bag.
    /// </summary>
    public QuicListenerOptions()
    {
    }

    /// <summary>
    /// Gets or sets the local endpoint to bind.
    /// </summary>
    public IPEndPoint ListenEndPoint { get; set; } = null!;

    /// <summary>
    /// Gets or sets the application protocols the listener will accept.
    /// </summary>
    public List<SslApplicationProtocol> ApplicationProtocols { get; set; } = null!;

    /// <summary>
    /// Gets or sets the backlog for pending connections.
    /// </summary>
    public int ListenBacklog { get; set; }

    /// <summary>
    /// Gets or sets the narrow server-side connection-options callback.
    /// </summary>
    public Func<QuicConnection, SslClientHelloInfo, CancellationToken, ValueTask<QuicServerConnectionOptions>> ConnectionOptionsCallback { get; set; } = null!;

    // CONTEXT: Internal-only Stage 4 connection-start policy controls. The
    // selected shard remains immutable for the connection lifetime.
    internal QuicConnectionShardPlacementObservationMode
        ConnectionShardPlacementObservationMode { get; set; }

    internal QuicConnectionShardPlacementPolicyValue?
        ForcedConnectionShardPlacementPolicyValue { get; set; }

    internal void Validate(string argumentName)
    {
        if (ListenEndPoint is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (ApplicationProtocols is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (ApplicationProtocols.Count == 0)
        {
            throw new ArgumentException("At least one application protocol is required.", argumentName);
        }

        if (ConnectionOptionsCallback is null)
        {
            throw new ArgumentNullException(argumentName);
        }

        if (ListenBacklog < 0)
        {
            throw new ArgumentOutOfRangeException(argumentName);
        }

        if (ListenBacklog == 0)
        {
            ListenBacklog = DefaultListenBacklog;
        }

        QuicConnectionShardPlacementPolicy.ValidateObservationMode(
            ConnectionShardPlacementObservationMode);
        if (ForcedConnectionShardPlacementPolicyValue is { } forced)
        {
            QuicConnectionShardPlacementPolicy.ValidateValue(forced);
        }
    }
}
