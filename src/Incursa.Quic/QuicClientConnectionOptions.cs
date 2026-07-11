// Copyright (c) 2026 Incursa LLC.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

using System.Net;
using System.Net.Security;

namespace Incursa.Quic;

// CONTEXT: The client options bag keeps transport and TLS inputs together because the managed
// client setup path consumes them as one configuration snapshot, not as independently mutable knobs.
// SEE: QuicClientConnectionHost
/// <summary>
/// Client-side connection options consumed by <see cref="QuicConnection.ConnectAsync(QuicClientConnectionOptions, CancellationToken)"/>.
/// </summary>
public sealed class QuicClientConnectionOptions : QuicConnectionOptions
{
    /// <summary>
    /// Gets or sets the client authentication options.
    /// </summary>
    public SslClientAuthenticationOptions ClientAuthenticationOptions { get; set; } = null!;

    /// <summary>
    /// Gets or sets the optional local endpoint to bind before connecting.
    /// </summary>
    public IPEndPoint? LocalEndPoint { get; set; }

    /// <summary>
    /// Gets or sets the narrow peer-certificate policy carrier used by the managed client exact-match floor.
    /// </summary>
    public QuicPeerCertificatePolicy? PeerCertificatePolicy { get; set; }

    /// <summary>
    /// Gets or sets an opaque resumption ticket previously exported from another connection.
    /// </summary>
    public QuicResumptionTicket? ResumptionTicket { get; set; }

    /// <summary>
    /// Gets or sets the TLS cipher suite selected for the managed client handshake slice.
    /// </summary>
    internal QuicTlsCipherSuite? SelectedCipherSuite { get; set; }

    /// <summary>
    /// Gets or sets the remote endpoint to connect.
    /// </summary>
    public EndPoint RemoteEndPoint { get; set; } = null!;
}
