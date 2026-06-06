// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

namespace Incursa.Quic;

// CONTEXT: These defaults bound the initial memory footprint for connection and stream receive
// windows before applications override them, so the constructor preserves the conservative baseline.
// SEE: QuicConnectionOptions
/// <summary>
/// Receive-window settings for a connection and its streams.
/// </summary>
public sealed class QuicReceiveWindowSizes
{
    private const int DefaultConnectionReceiveWindow = 16 * 1024 * 1024;
    private const int DefaultStreamReceiveWindow = 64 * 1024;

    /// <summary>
    /// Initializes a new instance of the <see cref="QuicReceiveWindowSizes"/> class.
    /// </summary>
    public QuicReceiveWindowSizes()
    {
        Connection = DefaultConnectionReceiveWindow;
        LocallyInitiatedBidirectionalStream = DefaultStreamReceiveWindow;
        RemotelyInitiatedBidirectionalStream = DefaultStreamReceiveWindow;
        UnidirectionalStream = DefaultStreamReceiveWindow;
    }

    /// <summary>
    /// Gets or sets the connection-level receive window.
    /// </summary>
    public int Connection { get; set; }

    /// <summary>
    /// Gets or sets the receive window for locally initiated bidirectional streams.
    /// </summary>
    public int LocallyInitiatedBidirectionalStream { get; set; }

    /// <summary>
    /// Gets or sets the receive window for remotely initiated bidirectional streams.
    /// </summary>
    public int RemotelyInitiatedBidirectionalStream { get; set; }

    /// <summary>
    /// Gets or sets the receive window for unidirectional streams.
    /// </summary>
    public int UnidirectionalStream { get; set; }
}
